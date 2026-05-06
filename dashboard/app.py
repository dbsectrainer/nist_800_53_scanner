#!/usr/bin/env python3
"""
NIST 800-53 Compliance Dashboard

Flask application providing a web-based compliance monitoring interface and
25+ API endpoints backed by real scanner report data.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, date, timezone
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path setup — must happen before local imports
# ---------------------------------------------------------------------------

_DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_DASHBOARD_DIR)

# Ensure project root is on sys.path so modules/ is importable
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Ensure dashboard directory is on sys.path for local modules
if _DASHBOARD_DIR not in sys.path:
    sys.path.insert(0, _DASHBOARD_DIR)

# ---------------------------------------------------------------------------
# Web framework
# ---------------------------------------------------------------------------

from flask import (
    Flask,
    Response,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_cors import CORS
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, Info, generate_latest

# ---------------------------------------------------------------------------
# Dashboard-local modules
# ---------------------------------------------------------------------------

import models
from data_manager import (
    FAMILY_NAMES,
    MetricsCalculator,
    ReportMeta,
    RiskScorer,
    TrendAnalyzer,
    build_data_manager,
)
from poam_generator import sync_poam_from_report

# ---------------------------------------------------------------------------
# Project-root modules (optional — graceful degradation when absent)
# ---------------------------------------------------------------------------

try:
    from modules.encryption import SecureDataHandler, SecureKeyStorage  # noqa: F401
except ImportError:
    SecureDataHandler = None  # type: ignore[assignment,misc]
    SecureKeyStorage = None   # type: ignore[assignment,misc]

try:
    from modules.report_versioning import ReportVersionManager  # noqa: F401
except ImportError:
    ReportVersionManager = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row (or plain dict) to a plain dict."""
    if row is None:
        return {}
    if isinstance(row, dict):
        return dict(row)
    try:
        return dict(row)
    except Exception:
        return {}


def _rows_to_list(rows) -> List[dict]:
    """Convert a list of sqlite3.Row objects to a list of dicts."""
    return [_row_to_dict(r) for r in (rows or [])]


# Prometheus metrics for Grafana (scraped at GET /metrics; unauthenticated).
_MET_COMPLIANCE = Gauge(
    "nist_dashboard_compliance_pct",
    "Overall NIST control compliance percentage from the latest scan",
)
_MET_CONTROLS_TOTAL = Gauge(
    "nist_dashboard_controls_total",
    "Total controls evaluated in the latest scan",
)
_MET_CONTROLS_COMPLIANT = Gauge(
    "nist_dashboard_controls_compliant",
    "Compliant controls in the latest scan",
)
_MET_CONTROLS_NON_COMPLIANT = Gauge(
    "nist_dashboard_controls_non_compliant",
    "Non-compliant controls in the latest scan",
)
_MET_POAM_OPEN = Gauge(
    "nist_dashboard_poam_open",
    "Open or in-progress POA&M items",
)
_MET_POAM_CRITICAL_OPEN = Gauge(
    "nist_dashboard_poam_critical_open",
    "Open or in-progress POA&M items with critical or high severity",
)
_MET_FAMILY_COMPLIANCE = Gauge(
    "nist_dashboard_family_compliance_pct",
    "Compliance percentage by NIST control family",
    ["family"],
)
_MET_DATA_AVAILABLE = Gauge(
    "nist_dashboard_data_available",
    "1 if decryptable latest scan data is loaded, 0 otherwise",
)
_MET_REPORT_INFO = Info(
    "nist_dashboard_latest_report",
    "Metadata for the report backing current dashboard metrics",
)


def _today_str() -> str:
    return date.today().isoformat()


def _aging_bucket(days: float) -> str:
    if days < 30:
        return "<30"
    if days < 60:
        return "30-60"
    if days < 90:
        return "60-90"
    return ">90"


# ---------------------------------------------------------------------------
# ComplianceDashboard
# ---------------------------------------------------------------------------


class ComplianceDashboard:
    """Flask-based NIST 800-53 compliance monitoring dashboard."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.app = Flask(__name__)
        CORS(self.app)

        self.config = self._load_configuration(config_path)
        self.app.secret_key = self.config.get("secret_key", os.urandom(24))

        # Paths
        self.project_root = _PROJECT_ROOT
        self.reports_dir = os.path.join(self.project_root, "reports")

        # Database
        db_cfg = self.config.get("database", {})
        db_path = db_cfg.get(
            "path",
            os.path.join(_DASHBOARD_DIR, "dashboard.db"),
        )
        self.db_path = db_path
        models.init_db(db_path)

        # Data layer
        self.report_reader, self.trend_analyzer = build_data_manager(self.project_root)

        # Sync existing reports into scan_history on startup
        self._sync_scan_history_on_startup()

        # Logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        self.logger = logging.getLogger(__name__)

        # Teardown: close per-request DB connection
        self.app.teardown_appcontext(self._teardown_db)

        self._setup_routes()

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def _load_configuration(self, config_path: Optional[str]) -> dict:
        """Load dashboard configuration from JSON or YAML file."""
        defaults: dict = {
            "app_name": "NIST 800-53 Compliance Dashboard",
            "debug_mode": False,
            "port": 5001,
        }

        if not config_path:
            # Try conventional locations
            for candidate in (
                os.path.join(_DASHBOARD_DIR, "config", "development.yaml"),
                os.path.join(_DASHBOARD_DIR, "config.yaml"),
                os.path.join(_DASHBOARD_DIR, "config.json"),
            ):
                if os.path.exists(candidate):
                    config_path = candidate
                    break

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as fh:
                    content = fh.read()
                # YAML files need PyYAML; fall back to JSON if unavailable
                if config_path.endswith((".yaml", ".yml")):
                    try:
                        import yaml  # type: ignore[import]
                        loaded = yaml.safe_load(content)
                    except ImportError:
                        self.logger.warning(
                            "PyYAML not installed; skipping YAML config %s", config_path
                        )
                        loaded = {}
                else:
                    loaded = json.loads(content)

                if isinstance(loaded, dict):
                    # Flatten common YAML nesting (app.secret_key, database.path, …)
                    app_section = loaded.get("app", {})
                    if isinstance(app_section, dict):
                        defaults.update(app_section)
                    db_section = loaded.get("database", {})
                    if isinstance(db_section, dict):
                        defaults["database"] = db_section
                    defaults.update(
                        {k: v for k, v in loaded.items() if k not in ("app", "database")}
                    )
            except Exception as exc:
                print(f"Configuration load failed ({config_path}): {exc}")

        port_env = os.environ.get("DASHBOARD_PORT") or os.environ.get("PORT")
        if port_env:
            try:
                defaults["port"] = int(port_env)
            except ValueError:
                pass

        return defaults

    # ------------------------------------------------------------------
    # Database helpers
    # ------------------------------------------------------------------

    def get_db(self):
        """Return the per-request DB connection, creating it if needed."""
        if "db" not in g:
            g.db = models.get_db(self.db_path)
        return g.db

    def _teardown_db(self, exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # ------------------------------------------------------------------
    # Startup helpers
    # ------------------------------------------------------------------

    def _sync_scan_history_on_startup(self) -> None:
        """Populate scan_history table from existing report files on first run."""
        db = models.get_db(self.db_path)
        try:
            reports = self.report_reader.list_reports()
            for meta in reports:
                db.execute(
                    """
                    INSERT OR IGNORE INTO scan_history
                        (report_id, scan_date, total_controls, compliant_count, compliance_pct)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        meta.report_id,
                        meta.scan_date.isoformat(),
                        meta.total_controls,
                        meta.compliant_count,
                        meta.compliance_pct,
                    ),
                )
            db.commit()
        except Exception as exc:
            logging.getLogger(__name__).error(
                "scan_history sync failed on startup: %s", exc
            )
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Auth decorator
    # ------------------------------------------------------------------

    def require_auth(self, f):
        """Decorator: return 401 JSON when session has no authenticated user."""

        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get("user"):
                return jsonify({"error": "Unauthorized", "message": "Authentication required"}), 401
            return f(*args, **kwargs)

        return decorated

    # ------------------------------------------------------------------
    # Route registration
    # ------------------------------------------------------------------

    def _setup_routes(self) -> None:
        ra = self.require_auth

        # Auth
        self.app.route("/login", methods=["GET", "POST"])(self.login)
        self.app.route("/logout", methods=["POST"])(self.logout)

        # Prometheus (no auth — scrape from internal network only in production)
        self.app.route("/metrics", methods=["GET"])(self.prometheus_metrics)

        # Pages
        self.app.route("/", methods=["GET"])(self.index)
        self.app.route("/dashboard", methods=["GET"])(ra(self.dashboard))

        # v2 API
        self.app.route("/api/v2/posture", methods=["GET"])(ra(self.api_posture))
        self.app.route("/api/v2/families", methods=["GET"])(ra(self.api_families))
        self.app.route("/api/v2/families/<family>", methods=["GET"])(ra(self.api_family_detail))
        self.app.route("/api/v2/controls", methods=["GET"])(ra(self.api_controls))
        self.app.route("/api/v2/controls/<control_id>", methods=["GET"])(ra(self.api_control_detail))
        self.app.route("/api/v2/poam", methods=["GET"])(ra(self.api_poam_list))
        self.app.route("/api/v2/poam/<int:item_id>", methods=["PUT"])(ra(self.api_poam_update))
        self.app.route("/api/v2/poam/sync", methods=["POST"])(ra(self.api_poam_sync))
        self.app.route("/api/v2/risk", methods=["GET"])(ra(self.api_risk))
        self.app.route("/api/v2/assessments", methods=["GET"])(ra(self.api_assessments))
        self.app.route("/api/v2/assessments/<report_id>", methods=["GET"])(ra(self.api_assessment_detail))
        self.app.route("/api/v2/monitoring", methods=["GET"])(ra(self.api_monitoring))
        self.app.route("/api/v2/monitoring/<control_id>", methods=["PUT"])(ra(self.api_monitoring_update))
        self.app.route("/api/v2/evidence", methods=["GET"])(ra(self.api_evidence_list))
        self.app.route("/api/v2/evidence", methods=["POST"])(ra(self.api_evidence_create))
        self.app.route("/api/v2/evidence/<int:ev_id>", methods=["PUT"])(ra(self.api_evidence_update))
        self.app.route("/api/v2/evidence/<int:ev_id>", methods=["DELETE"])(ra(self.api_evidence_delete))
        self.app.route("/api/v2/assets", methods=["GET"])(ra(self.api_assets_list))
        self.app.route("/api/v2/assets", methods=["POST"])(ra(self.api_assets_create))
        self.app.route("/api/v2/owners", methods=["GET"])(ra(self.api_owners_list))
        self.app.route("/api/v2/owners", methods=["POST"])(ra(self.api_owners_create))
        self.app.route("/api/v2/owners/<int:owner_id>", methods=["PUT"])(ra(self.api_owners_update))
        self.app.route("/api/v2/exceptions", methods=["GET"])(ra(self.api_exceptions_list))
        self.app.route("/api/v2/exceptions", methods=["POST"])(ra(self.api_exceptions_create))
        self.app.route("/api/v2/exceptions/<int:ex_id>", methods=["PUT"])(ra(self.api_exceptions_update))
        self.app.route("/api/v2/trends", methods=["GET"])(ra(self.api_trends))
        self.app.route("/api/v2/integrations", methods=["GET"])(ra(self.api_integrations))
        self.app.route("/api/v2/view/<role>", methods=["GET"])(ra(self.api_role_view))
        self.app.route("/api/v2/scan/trigger", methods=["POST"])(ra(self.api_scan_trigger))
        self.app.route("/api/v2/scan/reports", methods=["GET"])(ra(self.api_scan_reports))

        # Legacy backward-compat endpoints
        self.app.route("/api/compliance_status", methods=["GET"])(ra(self.get_compliance_status))
        self.app.route("/api/vulnerability_summary", methods=["GET"])(ra(self.get_vulnerability_summary))
        self.app.route("/api/risk_assessment", methods=["GET"])(ra(self.get_risk_assessment))
        self.app.route("/api/compliance_frameworks", methods=["GET"])(ra(self.get_compliance_frameworks))

    # ------------------------------------------------------------------
    # Internal data helpers
    # ------------------------------------------------------------------

    def _load_latest(self) -> Tuple[Optional[ReportMeta], Optional[dict]]:
        """Return (meta, results) for the most recent report."""
        return self.report_reader.load_latest_report()

    def _no_data_response(self):
        return jsonify({"no_data": True, "message": "No scan data available"}), 200

    def _encrypted_response(self):
        return jsonify({"encrypted": True, "message": "Report data is encrypted and could not be decrypted"}), 200

    def _get_calculator(self) -> Tuple[Optional[MetricsCalculator], Optional[ReportMeta], Optional[Any]]:
        """
        Return (MetricsCalculator, ReportMeta, error_response).

        error_response is a Flask response tuple when data is unavailable.
        """
        meta, results = self._load_latest()
        if meta is None:
            return None, None, self._no_data_response()
        if results is None:
            return None, meta, self._encrypted_response()
        return MetricsCalculator(meta, results), meta, None

    def prometheus_metrics(self):
        """Expose Prometheus text format for Grafana (mirrors /api/v2/posture aggregates)."""
        meta, results = self._load_latest()
        db = self.get_db()

        def _zeros() -> Response:
            _MET_DATA_AVAILABLE.set(0)
            _MET_COMPLIANCE.set(0)
            _MET_CONTROLS_TOTAL.set(0)
            _MET_CONTROLS_COMPLIANT.set(0)
            _MET_CONTROLS_NON_COMPLIANT.set(0)
            _MET_POAM_OPEN.set(0)
            _MET_POAM_CRITICAL_OPEN.set(0)
            _MET_REPORT_INFO.info({"report_id": "", "last_scan_date": ""})
            return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

        if meta is None:
            return _zeros()

        if results is None:
            _MET_DATA_AVAILABLE.set(0)
            _MET_COMPLIANCE.set(0)
            _MET_CONTROLS_TOTAL.set(float(meta.total_controls))
            _MET_CONTROLS_COMPLIANT.set(float(meta.compliant_count))
            non_comp = max(0, meta.total_controls - meta.compliant_count)
            _MET_CONTROLS_NON_COMPLIANT.set(float(non_comp))
            _MET_POAM_OPEN.set(0)
            _MET_POAM_CRITICAL_OPEN.set(0)
            _MET_REPORT_INFO.info(
                {
                    "report_id": meta.report_id or "",
                    "last_scan_date": meta.scan_date.isoformat() if meta.scan_date else "",
                }
            )
            return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

        calc = MetricsCalculator(meta, results)
        overall = calc.get_overall_compliance()
        open_count = db.execute(
            "SELECT COUNT(*) FROM poam_items WHERE status IN ('open','in_progress')"
        ).fetchone()[0]
        critical_count = db.execute(
            "SELECT COUNT(*) FROM poam_items WHERE status IN ('open','in_progress') "
            "AND severity IN ('critical','high')"
        ).fetchone()[0]

        _MET_DATA_AVAILABLE.set(1)
        _MET_COMPLIANCE.set(float(overall.compliance_pct))
        _MET_CONTROLS_TOTAL.set(float(overall.total))
        _MET_CONTROLS_COMPLIANT.set(float(overall.compliant))
        _MET_CONTROLS_NON_COMPLIANT.set(float(overall.non_compliant))
        _MET_POAM_OPEN.set(float(open_count))
        _MET_POAM_CRITICAL_OPEN.set(float(critical_count))

        by_family = calc.get_compliance_by_family()
        for fm in by_family.values():
            _MET_FAMILY_COMPLIANCE.labels(family=fm.family).set(float(fm.compliance_pct))

        _MET_REPORT_INFO.info(
            {
                "report_id": meta.report_id or "",
                "last_scan_date": meta.scan_date.isoformat() if meta.scan_date else "",
            }
        )
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    def _get_active_exception_ids(self, db) -> List[str]:
        """Return list of control_ids that have an active exception."""
        rows = db.execute(
            "SELECT control_id FROM exceptions WHERE status = 'active'"
        ).fetchall()
        return [r["control_id"] for r in rows]

    def _enrich_controls_with_db(self, controls, db) -> List[dict]:
        """Add owner_name and poam_id fields to a list of control dicts."""
        enriched = []
        for ctrl in controls:
            cid = ctrl.get("control_id") if isinstance(ctrl, dict) else ctrl.control_id
            # Fetch owner
            owner_row = db.execute(
                "SELECT owner_name FROM control_owners WHERE control_id = ? LIMIT 1",
                (cid,),
            ).fetchone()
            # Fetch open poam_id
            poam_row = db.execute(
                "SELECT poam_id FROM poam_items WHERE control_id = ? AND status IN ('open','in_progress') LIMIT 1",
                (cid,),
            ).fetchone()

            if isinstance(ctrl, dict):
                entry = dict(ctrl)
            else:
                entry = {
                    "control_id": ctrl.control_id,
                    "family": ctrl.family,
                    "description": ctrl.description,
                    "compliant": ctrl.compliant,
                    "remediation": ctrl.remediation,
                    "last_assessed": ctrl.scan_date.isoformat() if ctrl.scan_date else None,
                }
            entry["owner_name"] = owner_row["owner_name"] if owner_row else None
            entry["poam_id"] = poam_row["poam_id"] if poam_row else None
            enriched.append(entry)
        return enriched

    # ------------------------------------------------------------------
    # Auth routes
    # ------------------------------------------------------------------

    def login(self):
        if request.method == "GET":
            if session.get("user"):
                return redirect(url_for("dashboard"))
            return render_template("login.html")

        body = request.get_json(silent=True) or {}
        username = body.get("username", "")
        password = body.get("password", "")

        # Simple dev auth — replace with real credential store for production
        valid = username == "admin" and password == "password"
        # Also support config-defined local users
        if not valid:
            for u in self.config.get("local_users", []):
                if u.get("username") == username and u.get("password") == password:
                    valid = True
                    break

        if valid:
            session["user"] = username
            session["role"] = "admin"
            return jsonify({"status": "success", "user": {"username": username}}), 200

        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

    def logout(self):
        session.clear()
        return jsonify({"status": "success"}), 200

    # ------------------------------------------------------------------
    # Page routes
    # ------------------------------------------------------------------

    def index(self):
        if session.get("user"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    def dashboard(self):
        return render_template("dashboard.html")

    # ------------------------------------------------------------------
    # v2 API: posture
    # ------------------------------------------------------------------

    def api_posture(self):
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None and meta is not None

        overall = calc.get_overall_compliance()
        db = self.get_db()

        open_count = db.execute(
            "SELECT COUNT(*) FROM poam_items WHERE status IN ('open','in_progress')"
        ).fetchone()[0]
        critical_count = db.execute(
            "SELECT COUNT(*) FROM poam_items WHERE status IN ('open','in_progress') AND severity IN ('critical','high')"
        ).fetchone()[0]

        families_summary = [
            {
                "family": fm.family,
                "full_name": fm.full_name,
                "pct": fm.compliance_pct,
            }
            for fm in sorted(overall.families.values(), key=lambda f: f.family)
        ]

        return jsonify(
            {
                "compliance_pct": overall.compliance_pct,
                "total_controls": overall.total,
                "compliant": overall.compliant,
                "non_compliant": overall.non_compliant,
                "ato_status": overall.ato_status,
                "last_scan_date": meta.scan_date.isoformat() if meta.scan_date else None,
                "report_id": meta.report_id,
                "open_poam_count": open_count,
                "critical_poam_count": critical_count,
                "families_summary": families_summary,
            }
        )

    # ------------------------------------------------------------------
    # v2 API: families
    # ------------------------------------------------------------------

    def api_families(self):
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None

        by_family = calc.get_compliance_by_family()
        families_list = [
            {
                "family": fm.family,
                "full_name": fm.full_name,
                "total": fm.total,
                "compliant": fm.compliant,
                "non_compliant": fm.non_compliant,
                "compliance_pct": fm.compliance_pct,
                "risk_score": fm.risk_score,
            }
            for fm in sorted(by_family.values(), key=lambda f: f.family)
        ]

        family_codes = [f["family"] for f in families_list]
        scores = [f["compliance_pct"] for f in families_list]

        return jsonify(
            {
                "families": families_list,
                "heatmap_data": {"families": family_codes, "scores": scores},
            }
        )

    def api_family_detail(self, family: str):
        family = family.upper()
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None

        by_family = calc.get_compliance_by_family()
        fm = by_family.get(family)
        if fm is None:
            return jsonify({"error": f"Family '{family}' not found in latest scan"}), 404

        db = self.get_db()
        controls = self._enrich_controls_with_db(fm.controls, db)

        return jsonify(
            {
                "family": family,
                "full_name": fm.full_name,
                "controls": controls,
            }
        )

    # ------------------------------------------------------------------
    # v2 API: controls
    # ------------------------------------------------------------------

    def api_controls(self):
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None

        flat = calc.get_control_flat_list()
        db = self.get_db()

        # Query param filters
        family_filter = request.args.get("family", "").upper() or None
        compliant_filter = request.args.get("compliant", "").lower() or None
        search_filter = request.args.get("search", "").lower() or None

        filtered = []
        for ctrl in flat:
            if family_filter and ctrl.family != family_filter:
                continue
            if compliant_filter == "true" and not ctrl.compliant:
                continue
            if compliant_filter == "false" and ctrl.compliant:
                continue
            if search_filter:
                haystack = (ctrl.control_id + " " + ctrl.description).lower()
                if search_filter not in haystack:
                    continue
            filtered.append(ctrl)

        enriched = self._enrich_controls_with_db(filtered, db)
        return jsonify({"controls": enriched, "total": len(enriched)})

    def api_control_detail(self, control_id: str):
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None

        flat = calc.get_control_flat_list()
        match = next((c for c in flat if c.control_id == control_id), None)
        if match is None:
            return jsonify({"error": f"Control '{control_id}' not found"}), 404

        db = self.get_db()

        owner_row = db.execute(
            "SELECT * FROM control_owners WHERE control_id = ? LIMIT 1",
            (control_id,),
        ).fetchone()

        poam_row = db.execute(
            "SELECT * FROM poam_items WHERE control_id = ? AND status IN ('open','in_progress') LIMIT 1",
            (control_id,),
        ).fetchone()

        evidence_rows = db.execute(
            "SELECT * FROM evidence WHERE control_id = ?",
            (control_id,),
        ).fetchall()

        return jsonify(
            {
                "control_id": match.control_id,
                "family": match.family,
                "full_name": FAMILY_NAMES.get(match.family, match.family),
                "description": match.description,
                "compliant": match.compliant,
                "remediation": match.remediation,
                "details": match.details,
                "last_assessed": match.scan_date.isoformat() if match.scan_date else None,
                "report_id": match.report_id,
                "owner": _row_to_dict(owner_row) if owner_row else None,
                "poam_item": _row_to_dict(poam_row) if poam_row else None,
                "evidence": _rows_to_list(evidence_rows),
            }
        )

    # ------------------------------------------------------------------
    # v2 API: POA&M
    # ------------------------------------------------------------------

    def api_poam_list(self):
        db = self.get_db()

        status_filter = request.args.get("status", "").lower() or None
        severity_filter = request.args.get("severity", "").lower() or None
        overdue_filter = request.args.get("overdue", "").lower() or None

        query = """
            SELECT p.*, o.owner_name
            FROM   poam_items p
            LEFT JOIN control_owners o ON p.owner_id = o.id
        """
        conditions: List[str] = []
        params: List[Any] = []

        if status_filter:
            conditions.append("p.status = ?")
            params.append(status_filter)
        if severity_filter:
            conditions.append("p.severity = ?")
            params.append(severity_filter)

        today = _today_str()
        if overdue_filter == "true":
            conditions.append(
                "(p.scheduled_completion_date < ? AND p.status IN ('open','in_progress'))"
            )
            params.append(today)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY p.created_at DESC"

        rows = db.execute(query, params).fetchall()

        items = []
        aging: Dict[str, int] = {"<30": 0, "30-60": 0, "60-90": 0, ">90": 0}

        for row in rows:
            item = _row_to_dict(row)
            created_at = item.get("created_at", "")
            try:
                created_dt = datetime.fromisoformat(created_at)
                days_open = (datetime.now(timezone.utc).replace(tzinfo=None) - created_dt).days
            except (ValueError, TypeError):
                days_open = 0

            bucket = _aging_bucket(days_open)
            aging[bucket] = aging.get(bucket, 0) + 1

            sched = item.get("scheduled_completion_date")
            is_overdue = (
                sched is not None
                and sched < today
                and item.get("status") in ("open", "in_progress")
            )

            item["days_open"] = days_open
            item["aging_bucket"] = bucket
            item["overdue"] = is_overdue
            items.append(item)

        summary = {
            "total": len(items),
            "aging": aging,
            "overdue_count": sum(1 for i in items if i["overdue"]),
        }

        return jsonify({"items": items, "summary": summary})

    def api_poam_update(self, item_id: int):
        db = self.get_db()

        existing = db.execute(
            "SELECT * FROM poam_items WHERE id = ?", (item_id,)
        ).fetchone()
        if existing is None:
            return jsonify({"error": "POA&M item not found"}), 404

        body = request.get_json(silent=True) or {}
        allowed = {
            "status", "owner_id", "scheduled_completion_date", "actual_completion_date"
        }
        updates = {k: v for k, v in body.items() if k in allowed}

        if not updates:
            return jsonify({"error": "No valid fields provided"}), 400

        # Auto-set actual_completion_date when closing
        if updates.get("status") == "closed" and "actual_completion_date" not in updates:
            updates["actual_completion_date"] = _today_str()

        updates["updated_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [item_id]
        db.execute(
            f"UPDATE poam_items SET {set_clause} WHERE id = ?", values  # noqa: S608
        )
        db.commit()

        updated = db.execute(
            "SELECT * FROM poam_items WHERE id = ?", (item_id,)
        ).fetchone()
        return jsonify(_row_to_dict(updated))

    def api_poam_sync(self):
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None and meta is not None

        db = self.get_db()
        flat = calc.get_control_flat_list()
        non_compliant = [c for c in flat if not c.compliant]
        created = sync_poam_from_report(non_compliant, meta.report_id, db)

        return jsonify(
            {
                "created": created,
                "message": f"Synced POA&M items from report {meta.report_id}; {created} new item(s) created.",
            }
        )

    # ------------------------------------------------------------------
    # v2 API: risk
    # ------------------------------------------------------------------

    def api_risk(self):
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None

        db = self.get_db()
        exception_ids = self._get_active_exception_ids(db)
        by_family = calc.get_compliance_by_family()

        family_risks = []
        family_scores: Dict[str, float] = {}

        for fm in sorted(by_family.values(), key=lambda f: f.family):
            score = RiskScorer.score_family(fm.controls, exceptions=exception_ids)
            residual_score = RiskScorer.score_family(
                [c for c in fm.controls if c.control_id not in exception_ids],
                exceptions=exception_ids,
            )
            family_scores[fm.family] = score
            family_risks.append(
                {
                    "family": fm.family,
                    "full_name": fm.full_name,
                    "inherent_score": score,
                    "residual_score": residual_score,
                    "risk_level": RiskScorer.risk_level(residual_score),
                    "exception_count": sum(
                        1 for c in fm.controls if c.control_id in exception_ids
                    ),
                }
            )

        aggregate = RiskScorer.score_aggregate(family_scores)

        # Risk trend from scan_history
        history_rows = db.execute(
            "SELECT scan_date, compliance_pct FROM scan_history ORDER BY scan_date ASC"
        ).fetchall()
        risk_trend = [
            {
                "date": r["scan_date"],
                "compliance_pct": r["compliance_pct"],
                "risk_score": round(10.0 * (1.0 - (r["compliance_pct"] or 0) / 100.0), 4),
            }
            for r in history_rows
        ]

        return jsonify(
            {
                "families": family_risks,
                "aggregate_risk_score": aggregate,
                "risk_level": RiskScorer.risk_level(aggregate),
                "risk_trend": risk_trend,
                "exception_count": len(exception_ids),
            }
        )

    # ------------------------------------------------------------------
    # v2 API: assessments
    # ------------------------------------------------------------------

    def api_assessments(self):
        db = self.get_db()

        history = _rows_to_list(
            db.execute(
                "SELECT * FROM scan_history ORDER BY scan_date DESC"
            ).fetchall()
        )

        # Evidence completeness: controls with at least one evidence record
        ev_control_ids = {
            r[0]
            for r in db.execute(
                "SELECT DISTINCT control_id FROM evidence"
            ).fetchall()
        }

        calc, meta, _ = self._get_calculator()
        total_controls = 0
        if calc:
            flat = calc.get_control_flat_list()
            total_controls = len(flat)

        evidence_completeness = (
            round(len(ev_control_ids) / total_controls * 100.0, 2)
            if total_controls > 0
            else 0.0
        )

        failure_recurrence = self.trend_analyzer.get_failure_recurrence()
        top_recurring = sorted(
            failure_recurrence.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return jsonify(
            {
                "history": history,
                "total_scans": len(history),
                "evidence_completeness_pct": evidence_completeness,
                "top_recurring_failures": [
                    {"control_id": cid, "failure_count": cnt}
                    for cid, cnt in top_recurring
                ],
            }
        )

    def api_assessment_detail(self, report_id: str):
        results = self.report_reader.load_report(report_id)
        if results is None:
            return jsonify({"error": f"Report '{report_id}' not found or could not be decrypted"}), 404

        # Find meta
        metas = self.report_reader.list_reports()
        meta = next((m for m in metas if m.report_id == report_id), None)

        controls = []
        for category, ctrl_list in results.items():
            if not isinstance(ctrl_list, list):
                continue
            for raw in ctrl_list:
                if not isinstance(raw, dict):
                    continue
                controls.append(
                    {
                        "control_id": raw.get("control_id"),
                        "category": category,
                        "description": raw.get("description", ""),
                        "compliant": raw.get("compliant", False),
                        "remediation": raw.get("remediation", ""),
                    }
                )

        return jsonify(
            {
                "report_id": report_id,
                "scan_date": meta.scan_date.isoformat() if meta else None,
                "controls": controls,
                "total": len(controls),
            }
        )

    # ------------------------------------------------------------------
    # v2 API: monitoring
    # ------------------------------------------------------------------

    def api_monitoring(self):
        calc, meta, err = self._get_calculator()
        if err:
            return err
        assert calc is not None

        db = self.get_db()
        flat = calc.get_control_flat_list()
        all_control_ids = {c.control_id for c in flat}

        schedule_rows = _rows_to_list(
            db.execute("SELECT * FROM monitoring_schedule ORDER BY control_id").fetchall()
        )

        scheduled_ids = set()
        automated = manual = overdue = 0

        enriched = []
        for row in schedule_rows:
            cid = row.get("control_id")
            scheduled_ids.add(cid)

            # SLA status: last_checked + sla_hours vs now
            last_checked = row.get("last_checked")
            sla_hours = row.get("sla_hours", 720)
            sla_overdue = False
            if last_checked:
                try:
                    lc_dt = datetime.fromisoformat(last_checked)
                    elapsed_hours = (datetime.now(timezone.utc).replace(tzinfo=None) - lc_dt).total_seconds() / 3600.0
                    sla_overdue = elapsed_hours > sla_hours
                except (ValueError, TypeError):
                    pass

            check_type = row.get("check_type", "manual")
            if check_type == "automated":
                automated += 1
            else:
                manual += 1
            if sla_overdue:
                overdue += 1

            row["sla_overdue"] = sla_overdue
            enriched.append(row)

        # Controls from latest scan that have no monitoring entry
        unscheduled = [
            {"control_id": cid, "check_frequency": None, "check_type": None, "sla_overdue": None}
            for cid in sorted(all_control_ids - scheduled_ids)
        ]

        return jsonify(
            {
                "schedule": enriched,
                "unscheduled_controls": unscheduled,
                "summary": {
                    "automated": automated,
                    "manual": manual,
                    "overdue": overdue,
                    "total_scheduled": len(enriched),
                    "total_unscheduled": len(unscheduled),
                },
            }
        )

    def api_monitoring_update(self, control_id: str):
        db = self.get_db()
        body = request.get_json(silent=True) or {}

        allowed = {"check_frequency", "check_type", "sla_hours"}
        updates = {k: v for k, v in body.items() if k in allowed}
        if not updates:
            return jsonify({"error": "No valid fields provided"}), 400

        updates["updated_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()

        existing = db.execute(
            "SELECT id FROM monitoring_schedule WHERE control_id = ?", (control_id,)
        ).fetchone()

        if existing:
            set_clause = ", ".join(f"{k} = ?" for k in updates)
            db.execute(
                f"UPDATE monitoring_schedule SET {set_clause} WHERE control_id = ?",  # noqa: S608
                list(updates.values()) + [control_id],
            )
        else:
            updates["control_id"] = control_id
            cols = ", ".join(updates.keys())
            placeholders = ", ".join("?" for _ in updates)
            db.execute(
                f"INSERT INTO monitoring_schedule ({cols}) VALUES ({placeholders})",  # noqa: S608
                list(updates.values()),
            )

        db.commit()
        row = db.execute(
            "SELECT * FROM monitoring_schedule WHERE control_id = ?", (control_id,)
        ).fetchone()
        return jsonify(_row_to_dict(row))

    # ------------------------------------------------------------------
    # v2 API: evidence
    # ------------------------------------------------------------------

    def api_evidence_list(self):
        db = self.get_db()
        control_id = request.args.get("control_id")

        if control_id:
            rows = db.execute(
                "SELECT * FROM evidence WHERE control_id = ? ORDER BY created_at DESC",
                (control_id,),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM evidence ORDER BY created_at DESC"
            ).fetchall()

        today = date.today()
        items = []
        for row in rows:
            item = _row_to_dict(row)
            last_reviewed = item.get("last_reviewed")
            is_fresh = 0
            if last_reviewed:
                try:
                    lr = date.fromisoformat(last_reviewed[:10])
                    is_fresh = 1 if (today - lr).days <= 90 else 0
                except (ValueError, TypeError):
                    pass
            item["is_fresh"] = is_fresh
            items.append(item)

        # Identify controls with NO evidence from the latest scan
        missing: List[str] = []
        calc, _, _ = self._get_calculator()
        if calc:
            ev_control_ids = {i["control_id"] for i in items}
            flat = calc.get_control_flat_list()
            missing = sorted(
                {c.control_id for c in flat if c.control_id not in ev_control_ids}
            )

        return jsonify(
            {
                "evidence": items,
                "total": len(items),
                "controls_missing_evidence": missing,
                "summary": {
                    "fresh": sum(1 for i in items if i["is_fresh"]),
                    "stale": sum(1 for i in items if not i["is_fresh"]),
                },
            }
        )

    def api_evidence_create(self):
        db = self.get_db()
        body = request.get_json(silent=True) or {}

        control_id = body.get("control_id", "").strip()
        title = body.get("title", "").strip()
        if not control_id or not title:
            return jsonify({"error": "control_id and title are required"}), 400

        doc_type = body.get("doc_type")
        url = body.get("url")
        file_path = body.get("file_path")
        last_reviewed = body.get("last_reviewed")

        db.execute(
            """
            INSERT INTO evidence (control_id, title, doc_type, url, file_path, last_reviewed)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (control_id, title, doc_type, url, file_path, last_reviewed),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM evidence WHERE rowid = last_insert_rowid()"
        ).fetchone()
        return jsonify(_row_to_dict(row)), 201

    def api_evidence_update(self, ev_id: int):
        db = self.get_db()
        existing = db.execute("SELECT id FROM evidence WHERE id = ?", (ev_id,)).fetchone()
        if existing is None:
            return jsonify({"error": "Evidence record not found"}), 404

        body = request.get_json(silent=True) or {}
        allowed = {"title", "doc_type", "url", "file_path", "last_reviewed"}
        updates = {k: v for k, v in body.items() if k in allowed}
        if not updates:
            return jsonify({"error": "No valid fields provided"}), 400

        updates["updated_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        db.execute(
            f"UPDATE evidence SET {set_clause} WHERE id = ?",  # noqa: S608
            list(updates.values()) + [ev_id],
        )
        db.commit()
        row = db.execute("SELECT * FROM evidence WHERE id = ?", (ev_id,)).fetchone()
        return jsonify(_row_to_dict(row))

    def api_evidence_delete(self, ev_id: int):
        db = self.get_db()
        existing = db.execute("SELECT id FROM evidence WHERE id = ?", (ev_id,)).fetchone()
        if existing is None:
            return jsonify({"error": "Evidence record not found"}), 404

        db.execute("DELETE FROM evidence WHERE id = ?", (ev_id,))
        db.commit()
        return jsonify({"status": "deleted", "id": ev_id})

    # ------------------------------------------------------------------
    # v2 API: assets
    # ------------------------------------------------------------------

    def api_assets_list(self):
        db = self.get_db()
        rows = db.execute("SELECT * FROM assets ORDER BY created_at DESC").fetchall()
        return jsonify({"assets": _rows_to_list(rows), "total": len(rows)})

    def api_assets_create(self):
        db = self.get_db()
        body = request.get_json(silent=True) or {}
        asset_name = body.get("asset_name", "").strip()
        if not asset_name:
            return jsonify({"error": "asset_name is required"}), 400

        db.execute(
            """
            INSERT INTO assets (asset_name, asset_type, environment, applicable_families, owner_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                asset_name,
                body.get("asset_type"),
                body.get("environment"),
                body.get("applicable_families"),
                body.get("owner_id"),
            ),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM assets WHERE rowid = last_insert_rowid()"
        ).fetchone()
        return jsonify(_row_to_dict(row)), 201

    # ------------------------------------------------------------------
    # v2 API: owners
    # ------------------------------------------------------------------

    def api_owners_list(self):
        db = self.get_db()
        rows = db.execute("SELECT * FROM control_owners ORDER BY control_id").fetchall()
        return jsonify({"owners": _rows_to_list(rows), "total": len(rows)})

    def api_owners_create(self):
        db = self.get_db()
        body = request.get_json(silent=True) or {}
        control_id = body.get("control_id", "").strip()
        owner_name = body.get("owner_name", "").strip()
        if not control_id or not owner_name:
            return jsonify({"error": "control_id and owner_name are required"}), 400

        db.execute(
            """
            INSERT INTO control_owners (control_id, owner_name, owner_email, role, team)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                control_id,
                owner_name,
                body.get("owner_email"),
                body.get("role", "engineer"),
                body.get("team"),
            ),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM control_owners WHERE rowid = last_insert_rowid()"
        ).fetchone()
        return jsonify(_row_to_dict(row)), 201

    def api_owners_update(self, owner_id: int):
        db = self.get_db()
        existing = db.execute(
            "SELECT id FROM control_owners WHERE id = ?", (owner_id,)
        ).fetchone()
        if existing is None:
            return jsonify({"error": "Owner not found"}), 404

        body = request.get_json(silent=True) or {}
        allowed = {"owner_name", "owner_email", "role", "team"}
        updates = {k: v for k, v in body.items() if k in allowed}
        if not updates:
            return jsonify({"error": "No valid fields provided"}), 400

        updates["updated_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        db.execute(
            f"UPDATE control_owners SET {set_clause} WHERE id = ?",  # noqa: S608
            list(updates.values()) + [owner_id],
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM control_owners WHERE id = ?", (owner_id,)
        ).fetchone()
        return jsonify(_row_to_dict(row))

    # ------------------------------------------------------------------
    # v2 API: exceptions
    # ------------------------------------------------------------------

    def api_exceptions_list(self):
        db = self.get_db()
        rows = db.execute(
            "SELECT * FROM exceptions ORDER BY created_at DESC"
        ).fetchall()

        items = []
        for row in rows:
            item = _row_to_dict(row)
            exp_date = item.get("expiration_date")
            if exp_date:
                try:
                    exp_dt = date.fromisoformat(exp_date)
                    today_dt = date.today()
                    days_until_expiry = (exp_dt - today_dt).days
                    item["days_until_expiry"] = days_until_expiry
                    # Auto-expire
                    if days_until_expiry < 0 and item.get("status") == "active":
                        item["status"] = "expired"
                        db.execute(
                            "UPDATE exceptions SET status = 'expired' WHERE id = ?",
                            (item["id"],),
                        )
                except (ValueError, TypeError):
                    item["days_until_expiry"] = None
            else:
                item["days_until_expiry"] = None
            items.append(item)

        db.commit()
        return jsonify({"exceptions": items, "total": len(items)})

    def api_exceptions_create(self):
        db = self.get_db()
        body = request.get_json(silent=True) or {}
        control_id = body.get("control_id", "").strip()
        title = body.get("title", "").strip()
        if not control_id or not title:
            return jsonify({"error": "control_id and title are required"}), 400

        db.execute(
            """
            INSERT INTO exceptions
                (control_id, exception_type, title, justification,
                 compensating_control_desc, approved_by, expiration_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                control_id,
                body.get("exception_type"),
                title,
                body.get("justification"),
                body.get("compensating_control_desc"),
                body.get("approved_by"),
                body.get("expiration_date"),
                body.get("status", "active"),
            ),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM exceptions WHERE rowid = last_insert_rowid()"
        ).fetchone()
        return jsonify(_row_to_dict(row)), 201

    def api_exceptions_update(self, ex_id: int):
        db = self.get_db()
        existing = db.execute(
            "SELECT id FROM exceptions WHERE id = ?", (ex_id,)
        ).fetchone()
        if existing is None:
            return jsonify({"error": "Exception not found"}), 404

        body = request.get_json(silent=True) or {}
        allowed = {
            "exception_type", "title", "justification",
            "compensating_control_desc", "approved_by",
            "expiration_date", "status",
        }
        updates = {k: v for k, v in body.items() if k in allowed}
        if not updates:
            return jsonify({"error": "No valid fields provided"}), 400

        updates["updated_at"] = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
        set_clause = ", ".join(f"{k} = ?" for k in updates)
        db.execute(
            f"UPDATE exceptions SET {set_clause} WHERE id = ?",  # noqa: S608
            list(updates.values()) + [ex_id],
        )
        db.commit()
        row = db.execute("SELECT * FROM exceptions WHERE id = ?", (ex_id,)).fetchone()
        return jsonify(_row_to_dict(row))

    # ------------------------------------------------------------------
    # v2 API: trends
    # ------------------------------------------------------------------

    def api_trends(self):
        db = self.get_db()

        compliance_trend = self.trend_analyzer.get_compliance_trend()
        failure_recurrence = self.trend_analyzer.get_failure_recurrence()
        mttr = self.trend_analyzer.get_mttr(db)
        forecast = self.trend_analyzer.forecast_next_pct()

        # Scorecards
        current_pct = compliance_trend[-1]["pct"] if compliance_trend else 0.0
        previous_pct = compliance_trend[-2]["pct"] if len(compliance_trend) >= 2 else current_pct
        delta = round(current_pct - previous_pct, 2)

        top_recurring = sorted(
            failure_recurrence.items(), key=lambda x: x[1], reverse=True
        )[:5]

        avg_mttr = round(
            sum(mttr.values()) / len(mttr), 2
        ) if mttr else None

        return jsonify(
            {
                "compliance_trend": compliance_trend,
                "failure_recurrence": [
                    {"control_id": cid, "count": cnt} for cid, cnt in top_recurring
                ],
                "mttr_by_family": mttr,
                "forecast_next_pct": forecast,
                "scorecards": {
                    "current_compliance_pct": current_pct,
                    "previous_compliance_pct": previous_pct,
                    "delta": delta,
                    "avg_mttr_days": avg_mttr,
                    "forecast": forecast,
                },
            }
        )

    # ------------------------------------------------------------------
    # v2 API: integrations
    # ------------------------------------------------------------------

    def api_integrations(self):
        cfg = self.config
        integrations = []

        def _integration(name: str, label: str, path_keys: List[str]) -> dict:
            section = cfg
            for k in path_keys:
                if isinstance(section, dict):
                    section = section.get(k, {})
                else:
                    section = {}
            enabled = section.get("enabled", False) if isinstance(section, dict) else False
            return {"name": name, "label": label, "enabled": bool(enabled), "config": section if isinstance(section, dict) else {}}

        integrations.append(_integration("prometheus", "Prometheus Metrics", ["monitoring", "prometheus"]))
        integrations.append(_integration("jaeger", "Jaeger Tracing", ["monitoring", "tracing", "jaeger"]))
        integrations.append(_integration("slack", "Slack Notifications", ["notifications", "slack"]))
        integrations.append(_integration("email", "Email Notifications", ["notifications", "email"]))
        integrations.append(_integration("aws", "AWS Cloud", ["cloud_providers", "aws"]))
        integrations.append(_integration("azure", "Azure Cloud", ["cloud_providers", "azure"]))
        integrations.append(_integration("gcp", "Google Cloud Platform", ["cloud_providers", "gcp"]))

        return jsonify(
            {
                "integrations": integrations,
                "enabled_count": sum(1 for i in integrations if i["enabled"]),
                "total": len(integrations),
            }
        )

    # ------------------------------------------------------------------
    # v2 API: role view
    # ------------------------------------------------------------------

    def api_role_view(self, role: str):
        role = role.lower()
        valid_roles = {"executive", "isso", "auditor", "engineer"}
        if role not in valid_roles:
            return jsonify({"error": f"Unknown role '{role}'. Valid: {sorted(valid_roles)}"}), 400

        db = self.get_db()
        calc, meta, _ = self._get_calculator()
        overall = calc.get_overall_compliance() if calc else None
        by_family = calc.get_compliance_by_family() if calc else {}
        flat = calc.get_control_flat_list() if calc else []

        if role == "executive":
            open_critical = _rows_to_list(
                db.execute(
                    """
                    SELECT * FROM poam_items
                    WHERE status IN ('open','in_progress') AND severity IN ('critical','high')
                    ORDER BY severity, created_at
                    LIMIT 5
                    """
                ).fetchall()
            )
            family_scores = {
                fm: RiskScorer.score_family(by_family[fm].controls)
                for fm in by_family
            }
            return jsonify(
                {
                    "role": "executive",
                    "posture": {
                        "compliance_pct": overall.compliance_pct if overall else 0,
                        "ato_status": overall.ato_status if overall else "unknown",
                        "last_scan_date": meta.scan_date.isoformat() if meta and meta.scan_date else None,
                    },
                    "aggregate_risk_score": RiskScorer.score_aggregate(family_scores),
                    "open_critical_poams": open_critical,
                }
            )

        if role == "isso":
            poam_summary_row = db.execute(
                """
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status IN ('open','in_progress') THEN 1 ELSE 0 END) AS open_count,
                    SUM(CASE WHEN severity IN ('critical','high') AND status IN ('open','in_progress') THEN 1 ELSE 0 END) AS high_count
                FROM poam_items
                """
            ).fetchone()
            monitoring_overdue = db.execute(
                """
                SELECT COUNT(*) FROM monitoring_schedule
                WHERE next_due IS NOT NULL AND next_due < ?
                """,
                (_today_str(),),
            ).fetchone()[0]
            families_list = [
                {
                    "family": fm.family,
                    "full_name": fm.full_name,
                    "compliance_pct": fm.compliance_pct,
                    "non_compliant": fm.non_compliant,
                }
                for fm in sorted(by_family.values(), key=lambda f: f.family)
            ]
            return jsonify(
                {
                    "role": "isso",
                    "posture": {
                        "compliance_pct": overall.compliance_pct if overall else 0,
                        "ato_status": overall.ato_status if overall else "unknown",
                    },
                    "families": families_list,
                    "poam_summary": _row_to_dict(poam_summary_row),
                    "monitoring_overdue_count": monitoring_overdue,
                }
            )

        if role == "auditor":
            exceptions = _rows_to_list(
                db.execute("SELECT * FROM exceptions ORDER BY created_at DESC").fetchall()
            )
            evidence_rows = db.execute(
                "SELECT DISTINCT control_id FROM evidence"
            ).fetchall()
            ev_ids = {r[0] for r in evidence_rows}
            total_controls = len(flat)
            ev_completeness = (
                round(len(ev_ids) / total_controls * 100.0, 2)
                if total_controls > 0
                else 0.0
            )
            failed = [
                {"control_id": c.control_id, "description": c.description, "family": c.family}
                for c in flat
                if not c.compliant
            ]
            history = _rows_to_list(
                db.execute("SELECT * FROM scan_history ORDER BY scan_date DESC").fetchall()
            )
            return jsonify(
                {
                    "role": "auditor",
                    "assessments": history,
                    "evidence_completeness_pct": ev_completeness,
                    "exceptions": exceptions,
                    "failed_controls": failed,
                    "total_failed": len(failed),
                }
            )

        # engineer
        non_compliant = [
            {
                "control_id": c.control_id,
                "family": c.family,
                "description": c.description,
                "remediation": c.remediation,
            }
            for c in flat
            if not c.compliant
        ]
        schedule_rows = _rows_to_list(
            db.execute("SELECT * FROM monitoring_schedule ORDER BY control_id").fetchall()
        )
        ev_ids = {
            r[0]
            for r in db.execute("SELECT DISTINCT control_id FROM evidence").fetchall()
        }
        evidence_gaps = sorted(
            {c.control_id for c in flat if c.control_id not in ev_ids}
        )

        return jsonify(
            {
                "role": "engineer",
                "non_compliant_controls": non_compliant,
                "total_non_compliant": len(non_compliant),
                "monitoring_schedule": schedule_rows,
                "evidence_gaps": evidence_gaps,
            }
        )

    # ------------------------------------------------------------------
    # v2 API: scan
    # ------------------------------------------------------------------

    def api_scan_trigger(self):
        try:
            subprocess.Popen(  # noqa: S603, S607
                ["python", "scan.py"],
                cwd=self.project_root,
            )
        except Exception as exc:
            self.logger.error("Failed to trigger scan: %s", exc)
            return jsonify({"status": "error", "message": str(exc)}), 500

        return jsonify({"status": "triggered", "message": "Scan started in background"})

    def api_scan_reports(self):
        metas = self.report_reader.list_reports()
        return jsonify(
            {
                "reports": [
                    {
                        "report_id": m.report_id,
                        "scan_date": m.scan_date.isoformat(),
                        "total_controls": m.total_controls,
                        "compliant_count": m.compliant_count,
                        "compliance_pct": m.compliance_pct,
                    }
                    for m in metas
                ],
                "total": len(metas),
            }
        )

    # ------------------------------------------------------------------
    # Legacy backward-compat endpoints
    # ------------------------------------------------------------------

    def get_compliance_status(self):
        """Legacy /api/compliance_status — returns posture data in old format."""
        calc, meta, _ = self._get_calculator()
        if calc is None:
            return jsonify({"overall_compliance": 0, "frameworks": {}, "trend": []})

        overall = calc.get_overall_compliance()
        trend_data = self.trend_analyzer.get_compliance_trend()

        return jsonify(
            {
                "overall_compliance": overall.compliance_pct,
                "frameworks": {"NIST 800-53": overall.compliance_pct},
                "trend": [e["pct"] for e in trend_data],
                "ato_status": overall.ato_status,
                "last_scan_date": meta.scan_date.isoformat() if meta and meta.scan_date else None,
            }
        )

    def get_vulnerability_summary(self):
        """Legacy /api/vulnerability_summary — non-compliant controls as vulnerabilities."""
        calc, _, _ = self._get_calculator()
        if calc is None:
            return jsonify(
                {
                    "total_vulnerabilities": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "top_vulnerabilities": [],
                }
            )

        db = self.get_db()
        flat = calc.get_control_flat_list()
        non_compliant = [c for c in flat if not c.compliant]

        # Severity breakdown from poam_items
        sev_rows = db.execute(
            """
            SELECT severity, COUNT(*) as cnt
            FROM   poam_items
            WHERE  status IN ('open','in_progress')
            GROUP  BY severity
            """
        ).fetchall()
        sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in sev_rows:
            sev = row["severity"]
            if sev in sev_dist:
                sev_dist[sev] = row["cnt"]

        # Top non-compliant families
        from collections import Counter

        family_counts = Counter(c.family for c in non_compliant)
        top = [
            {"type": FAMILY_NAMES.get(f, f), "count": cnt}
            for f, cnt in family_counts.most_common(5)
        ]

        return jsonify(
            {
                "total_vulnerabilities": len(non_compliant),
                "severity_distribution": sev_dist,
                "top_vulnerabilities": top,
            }
        )

    def get_risk_assessment(self):
        """Legacy /api/risk_assessment — risk scores by family."""
        calc, _, _ = self._get_calculator()
        if calc is None:
            return jsonify(
                {
                    "overall_risk_score": 0,
                    "risk_categories": {},
                    "risk_trend": [],
                }
            )

        db = self.get_db()
        by_family = calc.get_compliance_by_family()
        family_scores = {
            fm: RiskScorer.score_family(by_family[fm].controls) for fm in by_family
        }
        aggregate = RiskScorer.score_aggregate(family_scores)

        history = db.execute(
            "SELECT compliance_pct FROM scan_history ORDER BY scan_date ASC"
        ).fetchall()
        risk_trend = [
            round(10.0 * (1.0 - (r["compliance_pct"] or 0) / 100.0), 4)
            for r in history
        ]

        return jsonify(
            {
                "overall_risk_score": aggregate,
                "risk_categories": {
                    FAMILY_NAMES.get(f, f): round(s, 4)
                    for f, s in family_scores.items()
                },
                "risk_trend": risk_trend,
            }
        )

    def get_compliance_frameworks(self):
        """Legacy /api/compliance_frameworks — family breakdown."""
        calc, _, _ = self._get_calculator()
        if calc is None:
            return jsonify({})

        by_family = calc.get_compliance_by_family()
        frameworks = {
            "NIST 800-53": {
                "compliance_score": (
                    round(
                        sum(fm.compliance_pct for fm in by_family.values()) / len(by_family), 2
                    )
                    if by_family
                    else 0.0
                ),
                "key_controls": [
                    {
                        "family": fm.family,
                        "full_name": fm.full_name,
                        "compliance_pct": fm.compliance_pct,
                        "total": fm.total,
                        "compliant": fm.compliant,
                    }
                    for fm in sorted(by_family.values(), key=lambda f: f.family)
                ],
            }
        }
        return jsonify(frameworks)

    # ------------------------------------------------------------------
    # Application entry point
    # ------------------------------------------------------------------

    def run(self) -> None:
        try:
            self.app.run(
                host="0.0.0.0",
                port=self.config.get("port", 5001),
                debug=self.config.get("debug_mode", False),
            )
        except Exception as exc:
            print(f"Dashboard startup failed: {exc}")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    dashboard = ComplianceDashboard()
    dashboard.run()


if __name__ == "__main__":
    main()
