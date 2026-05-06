"""
poam_generator.py — Auto-generate POA&M items from non-compliant NIST 800-53 controls.

Responsibilities:
  - Derive severity from control family and keyword scanning
  - Generate sequential POAM IDs per calendar year
  - Sync newly non-compliant controls into the poam_items table
  - Schedule monitoring entries for each new POA&M item
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import List

from data_manager import ControlResult

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "AC": "high",
    "AT": "medium",
    "AU": "medium",
    "CA": "medium",
    "CM": "medium",
    "CP": "medium",
    "IA": "high",
    "IR": "high",
    "MA": "low",
    "MP": "medium",
    "PE": "medium",
    "PL": "low",
    "PM": "low",
    "PS": "medium",
    "RA": "medium",
    "SA": "medium",
    "SC": "high",
    "SI": "medium",
    "SR": "medium",
}

DEFAULT_SEVERITY = "medium"

DUE_DATE_DAYS = {
    "critical": 30,
    "high": 90,
    "medium": 180,
    "low": 365,
}

# Keywords in description/remediation that bump severity to "high"
HIGH_SEVERITY_KEYWORDS = [
    "password", "credential", "encrypt", "privilege", "authentication",
    "firewall", "boundary", "intrusion", "unauthorized", "breach",
]


def derive_severity(control: ControlResult) -> str:
    """
    Derive severity from control family + keyword scan.

    1. Get base severity from SEVERITY_MAP (default: "medium")
    2. If base severity is "medium", scan control.description and control.remediation
       for HIGH_SEVERITY_KEYWORDS (case-insensitive). If any match, return "high".
    3. Return the (possibly bumped) severity.
    """
    base_severity = SEVERITY_MAP.get(control.family, DEFAULT_SEVERITY)

    if base_severity == "medium":
        combined_text = (
            (control.description or "") + " " + (control.remediation or "")
        ).lower()
        for keyword in HIGH_SEVERITY_KEYWORDS:
            if keyword in combined_text:
                return "high"

    return base_severity


def generate_poam_id(db_conn: sqlite3.Connection, year: int) -> str:
    """
    Generate next sequential POAM-YYYY-NNN ID.

    Counts existing poam_items WHERE strftime('%Y', created_at) = str(year).
    Returns f"POAM-{year}-{count+1:03d}"
    """
    cursor = db_conn.execute(
        "SELECT COUNT(*) FROM poam_items WHERE strftime('%Y', created_at) = ?",
        (str(year),),
    )
    count = cursor.fetchone()[0]
    return f"POAM-{year}-{count + 1:03d}"


def sync_poam_from_report(
    non_compliant_controls: List[ControlResult],
    report_id: str,
    db_conn: sqlite3.Connection,
) -> int:
    """
    Auto-generate POA&M items for newly non-compliant controls.

    For each control in non_compliant_controls:
    1. DEDUP: SELECT id FROM poam_items WHERE control_id = ? AND status IN ('open','in_progress')
       If row exists: skip (avoid duplicating open POA&Ms for same issue)
    2. Derive severity via derive_severity(control)
    3. Compute scheduled_completion_date as datetime.now() + DUE_DATE_DAYS[severity],
       formatted as "YYYY-MM-DD"
    4. Generate POAM ID via generate_poam_id(db_conn, current_year)
    5. Build title and description from control fields
    6. INSERT INTO poam_items
    7. INSERT OR IGNORE INTO monitoring_schedule

    Returns count of new POA&M items created.
    Commits after all inserts.
    Logs count created and any errors.
    """
    created_count = 0
    now = datetime.now()
    current_year = now.year

    for control in non_compliant_controls:
        try:
            # 1. Dedup: skip if an open or in-progress POA&M already exists
            cursor = db_conn.execute(
                "SELECT id FROM poam_items WHERE control_id = ? AND status IN ('open', 'in_progress')",
                (control.control_id,),
            )
            if cursor.fetchone() is not None:
                continue

            # 2. Derive severity
            severity = derive_severity(control)

            # 3. Compute scheduled completion date
            days_until_due = DUE_DATE_DAYS.get(severity, DUE_DATE_DAYS["medium"])
            due_date = now + timedelta(days=days_until_due)
            scheduled_completion_date = due_date.strftime("%Y-%m-%d")

            # 4. Generate POAM ID
            poam_id = generate_poam_id(db_conn, current_year)

            # 5. Build title and description
            title = f"Remediate {control.control_id}: {control.description[:80]}"
            description = control.remediation or control.description

            # 6. INSERT INTO poam_items
            db_conn.execute(
                """
                INSERT INTO poam_items (
                    poam_id, control_id, control_family, title, description,
                    severity, status, scheduled_completion_date,
                    auto_generated, source_report_id
                ) VALUES (?, ?, ?, ?, ?, ?, 'open', ?, 1, ?)
                """,
                (
                    poam_id,
                    control.control_id,
                    control.family,
                    title,
                    description,
                    severity,
                    scheduled_completion_date,
                    report_id,
                ),
            )

            # 7. INSERT OR IGNORE INTO monitoring_schedule
            db_conn.execute(
                """
                INSERT OR IGNORE INTO monitoring_schedule (
                    control_id, check_frequency, check_type,
                    last_checked, next_due
                ) VALUES (?, 'monthly', 'manual', ?, ?)
                """,
                (
                    control.control_id,
                    control.scan_date.isoformat(),
                    scheduled_completion_date,
                ),
            )

            created_count += 1

        except Exception as exc:
            logger.error(
                "Failed to create POA&M for control %s: %s",
                control.control_id,
                exc,
            )

    try:
        db_conn.commit()
    except Exception as exc:
        logger.error("Failed to commit POA&M inserts: %s", exc)
        raise

    logger.info("POA&M sync complete: %d new item(s) created from report %s", created_count, report_id)
    return created_count
