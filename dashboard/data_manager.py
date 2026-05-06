"""
data_manager.py — NIST 800-53 Dashboard data layer.

Responsibilities:
  - Discover and read scanner report JSON files from reports/
  - Decrypt encrypted report results using SecureDataHandler when available
  - Compute per-family and aggregate compliance metrics
  - Provide trend analysis and MTTR across historical scans
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Control-family metadata
# ---------------------------------------------------------------------------

FAMILY_NAMES: Dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

# Scan-result category keys produced by the scanner
_SCAN_CATEGORIES = {
    "access_control",
    "audit_logging",
    "network_security",
    "configuration_management",
    "incident_response",
}

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ControlResult:
    control_id: str
    family: str           # e.g. "AC" extracted from "AC-2"
    description: str
    compliant: bool
    remediation: str
    details: dict
    report_id: str
    scan_date: datetime


@dataclass
class FamilyMetrics:
    family: str
    full_name: str        # human-readable name from FAMILY_NAMES
    total: int
    compliant: int
    non_compliant: int
    compliance_pct: float
    risk_score: float     # 0.0–10.0 computed by RiskScorer
    controls: List[ControlResult] = field(default_factory=list)


@dataclass
class OverallMetrics:
    total: int
    compliant: int
    non_compliant: int
    compliance_pct: float
    ato_status: str       # "authorized" ≥90%, "conditional" ≥80%, "not_authorized" otherwise
    last_scan_date: Optional[datetime]
    families: Dict[str, FamilyMetrics]
    report_id: Optional[str]


@dataclass
class ReportMeta:
    report_id: str
    scan_date: datetime
    total_controls: int
    compliant_count: int
    compliance_pct: float


# ---------------------------------------------------------------------------
# RiskScorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """Stateless risk-scoring utilities for control families and aggregates."""

    CONTROL_WEIGHTS: Dict[str, float] = {
        "AC-2": 3.0, "AC-6": 3.0, "AC-17": 2.0,
        "SC-7": 3.0, "SC-5": 2.0, "SC-7(3)": 2.0, "SC-7(4)": 1.5, "SC-7(5)": 1.5,
        "AU-9": 2.5, "AU-2": 2.0, "AU-12": 1.5,
        "IR-4": 2.0, "IR-8": 2.0, "IR-4(1)": 1.5, "IR-2": 1.5, "IR-5": 1.5, "IR-6": 1.5,
        "CM-2": 1.0, "CM-6": 1.0, "CM-8": 1.0,
    }
    DEFAULT_WEIGHT: float = 1.5

    FAMILY_IMPACT: Dict[str, float] = {
        "AC": 1.3,
        "SC": 1.2,
        "IR": 1.1,
        "AU": 1.0,
        "CM": 0.9,
    }
    DEFAULT_FAMILY_IMPACT: float = 1.0

    @staticmethod
    def _weight(control_id: str) -> float:
        return RiskScorer.CONTROL_WEIGHTS.get(control_id, RiskScorer.DEFAULT_WEIGHT)

    @staticmethod
    def score_family(
        controls: List[ControlResult],
        exceptions: Optional[List[str]] = None,
    ) -> float:
        """
        Returns a 0.0–10.0 risk score for a single family.

        Score = (sum of weights for non-compliant & not-excepted controls)
                / (sum of all weights) * 10

        Args:
            controls: All ControlResult items in the family.
            exceptions: Control IDs that have an active exception
                        (excluded from the non-compliant tally).

        Returns:
            Risk score in [0.0, 10.0]. Returns 0.0 for empty families.
        """
        if not controls:
            return 0.0

        excepted: set = set(exceptions or [])
        total_weight = sum(RiskScorer._weight(c.control_id) for c in controls)
        if total_weight == 0.0:
            return 0.0

        failing_weight = sum(
            RiskScorer._weight(c.control_id)
            for c in controls
            if not c.compliant and c.control_id not in excepted
        )

        raw = (failing_weight / total_weight) * 10.0
        return round(min(max(raw, 0.0), 10.0), 4)

    @staticmethod
    def score_aggregate(family_scores: Dict[str, float]) -> float:
        """
        Weighted average of per-family scores using FAMILY_IMPACT multipliers.

        Args:
            family_scores: {family_code: score} mapping.

        Returns:
            Aggregate risk score in [0.0, 10.0]. Returns 0.0 for empty input.
        """
        if not family_scores:
            return 0.0

        total_impact = 0.0
        weighted_sum = 0.0
        for family, score in family_scores.items():
            impact = RiskScorer.FAMILY_IMPACT.get(family, RiskScorer.DEFAULT_FAMILY_IMPACT)
            weighted_sum += score * impact
            total_impact += impact

        if total_impact == 0.0:
            return 0.0

        raw = weighted_sum / total_impact
        return round(min(max(raw, 0.0), 10.0), 4)

    @staticmethod
    def risk_level(score: float) -> str:
        """
        Translate a numeric score into a human-readable risk level.

        Thresholds:
          < 3.0  → "low"
          < 6.0  → "medium"
          < 8.0  → "high"
          ≥ 8.0  → "critical"
        """
        if score < 3.0:
            return "low"
        if score < 6.0:
            return "medium"
        if score < 8.0:
            return "high"
        return "critical"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_datetime(value: str) -> Optional[datetime]:
    """Best-effort ISO-8601 datetime parse; returns None on failure."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        logger.debug("Could not parse datetime string %r", value)
        return None


def _is_encrypted_envelope(obj: object) -> bool:
    """Return True when obj looks like a SecureDataHandler envelope."""
    return (
        isinstance(obj, dict)
        and "data" in obj
        and "hmac" in obj
        and len(obj) == 2
    )


def _is_scan_results(obj: object) -> bool:
    """Return True when obj looks like a plain scan-results dict."""
    return isinstance(obj, dict) and bool(_SCAN_CATEGORIES & set(obj.keys()))


def _extract_family(control_id: str) -> str:
    """Extract family prefix from a control ID.

    Examples:
      "AC-2"     → "AC"
      "SC-7(3)"  → "SC"
      "IR-4(1)"  → "IR"
    """
    return control_id.split("-")[0].upper()


# ---------------------------------------------------------------------------
# ReportReader
# ---------------------------------------------------------------------------


class ReportReader:
    """Discover, read, and optionally decrypt scanner report JSON files."""

    def __init__(
        self,
        reports_dir: str,
        encryption_handler=None,
    ) -> None:
        """
        Args:
            reports_dir: Absolute path to the reports/ directory.
            encryption_handler: Optional SecureDataHandler instance. When None
                the reader attempts a graceful import from modules/; if that
                also fails it operates in plaintext-only mode.
        """
        self._reports_dir = Path(reports_dir)
        self._handler = encryption_handler

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_reports(self) -> List[ReportMeta]:
        """Return ReportMeta objects for every report file, newest first."""
        metas: List[ReportMeta] = []

        if not self._reports_dir.exists():
            logger.warning("Reports directory does not exist: %s", self._reports_dir)
            return metas

        for path in self._reports_dir.glob("*.json"):
            meta = self._read_meta(path)
            if meta is not None:
                metas.append(meta)

        metas.sort(key=lambda m: m.scan_date, reverse=True)
        return metas

    def load_report(self, report_id: str) -> Optional[dict]:
        """
        Load and return the decrypted results dict for *report_id*.

        Returns None when the file is not found or decryption fails.
        """
        if not self._reports_dir.exists():
            return None

        # Try exact filename match first, then scan all files.
        candidate = self._reports_dir / f"{report_id}.json"
        if candidate.exists():
            return self._load_results_from_path(candidate)

        for path in self._reports_dir.glob("*.json"):
            raw = self._read_json(path)
            if raw and raw.get("report_id") == report_id:
                return self._decrypt_results(raw.get("results"))

        logger.warning("Report not found: %s", report_id)
        return None

    def load_latest_report(self) -> Tuple[Optional[ReportMeta], Optional[dict]]:
        """
        Return ``(ReportMeta, results_dict)`` for the most recent report.

        Returns ``(None, None)`` when no reports exist.
        """
        metas = self.list_reports()
        if not metas:
            return None, None

        latest = metas[0]
        results = self.load_report(latest.report_id)
        return latest, results

    def load_all_reports(self) -> List[Tuple[ReportMeta, dict]]:
        """
        Return ``[(ReportMeta, results_dict), ...]`` for all readable reports,
        newest first. Unreadable or undecryptable reports are silently skipped.
        """
        output: List[Tuple[ReportMeta, dict]] = []
        for meta in self.list_reports():
            results = self.load_report(meta.report_id)
            if results is not None:
                output.append((meta, results))
        return output

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_json(self, path: Path) -> Optional[dict]:
        """Read and parse a JSON file; return None on any error."""
        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read %s: %s", path, exc)
            return None

    def _read_meta(self, path: Path) -> Optional[ReportMeta]:
        """Parse a report file into a ReportMeta, or return None."""
        raw = self._read_json(path)
        if not isinstance(raw, dict):
            return None

        report_id = raw.get("report_id") or path.stem
        scan_date = _parse_datetime(raw.get("timestamp", ""))
        if scan_date is None:
            # Fall back to file modification time
            scan_date = datetime.fromtimestamp(path.stat().st_mtime)

        # Quick-peek at results to get counts without full decryption
        results_field = raw.get("results")
        total = 0
        compliant = 0

        if isinstance(results_field, dict) and _is_scan_results(results_field):
            for controls in results_field.values():
                if isinstance(controls, list):
                    for ctrl in controls:
                        total += 1
                        if ctrl.get("compliant"):
                            compliant += 1
        # Encrypted reports: counts unavailable at meta stage — leave as 0

        pct = round((compliant / total * 100.0), 2) if total > 0 else 0.0
        return ReportMeta(
            report_id=report_id,
            scan_date=scan_date,
            total_controls=total,
            compliant_count=compliant,
            compliance_pct=pct,
        )

    def _load_results_from_path(self, path: Path) -> Optional[dict]:
        raw = self._read_json(path)
        if not raw:
            return None
        return self._decrypt_results(raw.get("results"))

    def _decrypt_results(self, results_field) -> Optional[dict]:
        """
        Resolve *results_field* to a plain scan-results dict.

        - Already a plain dict with scan category keys → return as-is.
        - Encrypted envelope (``{"data": ..., "hmac": ...}``) → decrypt.
        - Handler unavailable and envelope detected → return None gracefully.
        """
        if results_field is None:
            return None

        if _is_scan_results(results_field):
            return results_field

        if _is_encrypted_envelope(results_field):
            handler = self._get_handler()
            if handler is None:
                logger.warning(
                    "Results appear encrypted but no encryption handler is available; "
                    "skipping report."
                )
                return None
            try:
                decrypted = handler.decrypt_data(results_field)
                if isinstance(decrypted, dict) and _is_scan_results(decrypted):
                    return decrypted
                logger.warning(
                    "Decrypted payload does not look like scan results: %s",
                    type(decrypted),
                )
                return None
            except Exception as exc:
                logger.error("Decryption failed: %s", exc)
                return None

        # Unknown shape — return as-is if it's a dict (best-effort)
        if isinstance(results_field, dict):
            logger.debug("Unrecognised results shape; returning as-is.")
            return results_field

        logger.warning("Unexpected results type: %s", type(results_field))
        return None

    def _get_handler(self):
        """Return the encryption handler, attempting a lazy import if needed."""
        if self._handler is not None:
            return self._handler

        # Attempt a one-time lazy import
        try:
            from modules.encryption import SecureDataHandler, SecureKeyStorage  # noqa: PLC0415

            key_path = str(self._reports_dir.parent / ".keys" / "master.key")
            key_storage = SecureKeyStorage(key_path)
            self._handler = SecureDataHandler(key_storage)
            logger.info("Encryption handler loaded lazily from modules/encryption")
            return self._handler
        except Exception as exc:
            logger.debug("Lazy encryption import failed (%s); operating without decryption.", exc)
            return None


# ---------------------------------------------------------------------------
# MetricsCalculator
# ---------------------------------------------------------------------------


class MetricsCalculator:
    """Derive ControlResult, FamilyMetrics, and OverallMetrics from a report."""

    def __init__(self, report_meta: ReportMeta, results: dict) -> None:
        """
        Args:
            report_meta: Metadata for the scan (report_id, scan_date, …).
            results: Decrypted scan results dict with category-list values.
        """
        self._meta = report_meta
        self._results = results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_control_flat_list(self) -> List[ControlResult]:
        """
        Flatten all scan categories into a single list of ControlResult objects.

        The ``family`` field is derived from the control ID prefix
        (e.g. ``"AC-2"`` → ``"AC"``).
        """
        flat: List[ControlResult] = []
        for _, controls in self._results.items():
            if not isinstance(controls, list):
                continue
            for raw in controls:
                if not isinstance(raw, dict):
                    continue
                control_id = raw.get("control_id", "UNKNOWN")
                flat.append(
                    ControlResult(
                        control_id=control_id,
                        family=_extract_family(control_id),
                        description=raw.get("description", ""),
                        compliant=bool(raw.get("compliant", False)),
                        remediation=raw.get("remediation", ""),
                        details=raw.get("details") or {},
                        report_id=self._meta.report_id,
                        scan_date=self._meta.scan_date,
                    )
                )
        return flat

    def get_compliance_by_family(self) -> Dict[str, FamilyMetrics]:
        """
        Group controls by family and calculate per-family metrics.

        Returns a dict keyed by family code (e.g. ``"AC"``, ``"AU"``).
        """
        by_family: Dict[str, List[ControlResult]] = {}
        for ctrl in self.get_control_flat_list():
            by_family.setdefault(ctrl.family, []).append(ctrl)

        metrics: Dict[str, FamilyMetrics] = {}
        for family, controls in by_family.items():
            total = len(controls)
            compliant = sum(1 for c in controls if c.compliant)
            non_compliant = total - compliant
            pct = round((compliant / total * 100.0), 2) if total > 0 else 0.0
            risk = RiskScorer.score_family(controls)

            metrics[family] = FamilyMetrics(
                family=family,
                full_name=FAMILY_NAMES.get(family, family),
                total=total,
                compliant=compliant,
                non_compliant=non_compliant,
                compliance_pct=pct,
                risk_score=risk,
                controls=controls,
            )

        return metrics

    def get_overall_compliance(self) -> OverallMetrics:
        """
        Calculate top-level compliance metrics.

        ATO status thresholds:
          ≥ 90 % → "authorized"
          ≥ 80 % → "conditional"
          < 80 % → "not_authorized"
        """
        families = self.get_compliance_by_family()
        total = sum(f.total for f in families.values())
        compliant = sum(f.compliant for f in families.values())
        non_compliant = total - compliant
        pct = round((compliant / total * 100.0), 2) if total > 0 else 0.0

        if pct >= 90.0:
            ato_status = "authorized"
        elif pct >= 80.0:
            ato_status = "conditional"
        else:
            ato_status = "not_authorized"

        return OverallMetrics(
            total=total,
            compliant=compliant,
            non_compliant=non_compliant,
            compliance_pct=pct,
            ato_status=ato_status,
            last_scan_date=self._meta.scan_date,
            families=families,
            report_id=self._meta.report_id,
        )


# ---------------------------------------------------------------------------
# TrendAnalyzer
# ---------------------------------------------------------------------------


class TrendAnalyzer:
    """Historical trend analysis across all available reports."""

    def __init__(self, report_reader: ReportReader) -> None:
        self._reader = report_reader

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_compliance_trend(self) -> List[Dict]:
        """
        Return per-report compliance percentages, oldest first.

        Each entry: ``{"date": "ISO datetime string", "pct": float, "report_id": str}``
        """
        trend: List[Dict] = []
        for meta, results in self._reader.load_all_reports():
            calculator = MetricsCalculator(meta, results)
            overall = calculator.get_overall_compliance()
            trend.append(
                {
                    "date": meta.scan_date.isoformat(),
                    "pct": overall.compliance_pct,
                    "report_id": meta.report_id,
                }
            )

        # Sort oldest → newest (ascending date)
        trend.sort(key=lambda e: e["date"])
        return trend

    def get_failure_recurrence(self) -> Dict[str, int]:
        """
        Return ``{control_id: failure_count}`` tallied across all reports.

        Only non-compliant controls are counted.
        """
        counts: Dict[str, int] = {}
        for _, results in self._reader.load_all_reports():
            for controls in results.values():
                if not isinstance(controls, list):
                    continue
                for raw in controls:
                    if isinstance(raw, dict) and not raw.get("compliant", True):
                        cid = raw.get("control_id", "UNKNOWN")
                        counts[cid] = counts.get(cid, 0) + 1
        return counts

    def get_mttr(self, db_conn) -> Dict[str, float]:
        """
        Return ``{family: avg_days_to_close}`` for closed POAM items.

        Uses the ``poam_items`` table. Returns an empty dict when no closed
        items exist or the database is unavailable.

        Args:
            db_conn: An open ``sqlite3.Connection`` (with ``row_factory`` set).
        """
        if db_conn is None:
            return {}

        query = """
            SELECT control_family, created_at, actual_completion_date
            FROM   poam_items
            WHERE  status = 'closed'
              AND  actual_completion_date IS NOT NULL
        """
        try:
            cursor = db_conn.execute(query)
            rows = cursor.fetchall()
        except Exception as exc:
            logger.error("MTTR query failed: %s", exc)
            return {}

        if not rows:
            return {}

        family_days: Dict[str, List[float]] = {}
        for row in rows:
            family = row["control_family"] if hasattr(row, "keys") else row[0]
            created_raw = row["created_at"] if hasattr(row, "keys") else row[1]
            closed_raw = row["actual_completion_date"] if hasattr(row, "keys") else row[2]

            created = _parse_datetime(created_raw)
            closed = _parse_datetime(closed_raw)
            if created is None or closed is None:
                continue

            delta_days = (closed - created).total_seconds() / 86400.0
            if delta_days < 0:
                continue

            family_days.setdefault(family, []).append(delta_days)

        return {
            fam: round(sum(days) / len(days), 2)
            for fam, days in family_days.items()
            if days
        }

    def forecast_next_pct(self) -> float:
        """
        Project the next compliance percentage using simple linear regression
        over the last 3 or more data points.

        Falls back to the most recent known value when fewer than 2 points
        are available. Result is capped at 100.0.
        """
        trend = self.get_compliance_trend()
        if not trend:
            return 0.0
        if len(trend) < 2:
            return trend[-1]["pct"]

        # Use last 3 points (or all if fewer)
        window = trend[-3:] if len(trend) >= 3 else trend
        n = len(window)
        xs = list(range(n))
        ys = [entry["pct"] for entry in window]

        # Least-squares slope and intercept
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        ss_xy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
        ss_xx = sum((x - mean_x) ** 2 for x in xs)

        if ss_xx == 0.0:
            return min(mean_y, 100.0)

        slope = ss_xy / ss_xx
        intercept = mean_y - slope * mean_x
        projected = slope * n + intercept  # one step beyond the window
        return round(min(max(projected, 0.0), 100.0), 2)


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def build_data_manager(project_root: str) -> Tuple[ReportReader, TrendAnalyzer]:
    """
    Convenience factory that wires up a ``ReportReader`` and
    ``TrendAnalyzer`` for *project_root*.

    Attempts to load the encryption handler from
    ``<project_root>/.keys/master.key``. If the key file is absent or the
    import fails the reader is returned without decryption capability
    (plaintext-only mode).

    Args:
        project_root: Absolute path to the repository root.

    Returns:
        ``(reader, trend_analyzer)`` tuple.
    """
    root = Path(project_root)
    reports_dir = str(root / "reports")

    # Add project root to sys.path so modules/ is importable
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)

    encryption_handler = None
    key_path = root / ".keys" / "master.key"

    if key_path.exists():
        try:
            from modules.encryption import SecureDataHandler, SecureKeyStorage  # noqa: PLC0415

            key_storage = SecureKeyStorage(str(key_path))
            encryption_handler = SecureDataHandler(key_storage)
            logger.info("Encryption handler initialised from %s", key_path)
        except Exception as exc:
            logger.warning(
                "Could not initialise encryption handler from %s: %s — "
                "operating in plaintext-only mode.",
                key_path,
                exc,
            )
    else:
        logger.info(
            "Master key not found at %s; encryption disabled for dashboard reader.",
            key_path,
        )

    reader = ReportReader(reports_dir=reports_dir, encryption_handler=encryption_handler)
    trend_analyzer = TrendAnalyzer(report_reader=reader)
    return reader, trend_analyzer
