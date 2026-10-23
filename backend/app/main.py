from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sqlite3
import uuid
import ipaddress
import json

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from typing import Literal

# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "sentinelx.db"

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 5


# ==================================================
# DATABASE
# ==================================================

def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                hostname TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                raw_event TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                hostname TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                description TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                investigation_notes TEXT NOT NULL DEFAULT '',
closure_comment TEXT NOT NULL DEFAULT '',
updated_at TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                hostname TEXT PRIMARY KEY,
                os_name TEXT,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
        """)
def migrate_alerts_table():
    with get_connection() as conn:
        existing_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
        }

        migrations = {
            "investigation_notes":
                "ALTER TABLE alerts ADD COLUMN investigation_notes TEXT NOT NULL DEFAULT ''",
            "closure_comment":
                "ALTER TABLE alerts ADD COLUMN closure_comment TEXT NOT NULL DEFAULT ''",
            "updated_at":
                "ALTER TABLE alerts ADD COLUMN updated_at TEXT",
        }

        for column_name, sql in migrations.items():
            if column_name not in existing_columns:
                conn.execute(sql)        


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    migrate_alerts_table()
    yield


app = FastAPI(
    title="SentinelX SOC Platform",
    description="SOC monitoring, alert triage, and threat detection home lab.",
    version="0.2.0",
    lifespan=lifespan,
)


# ==================================================
# INPUT VALIDATION
# ==================================================

class SecurityEvent(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    hostname: str = Field(min_length=1, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    source_ip: str | None = None
    timestamp: datetime | None = None
    os_name: str | None = Field(default=None, max_length=100)
    source: str = Field(default="synthetic", max_length=100)

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value):
        if value is not None:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValueError("source_ip must be a valid IP address")
        return value


# ==================================================
# HOME AND HEALTH
# ==================================================

@app.get("/")
def home():
    return {
        "name": "SentinelX",
        "version": "0.2.0",
        "status": "running",
        "message": "Welcome to your SOC platform!"
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "sentinelx-api"
    }


# ==================================================
# EVENT INGESTION
# ==================================================

@app.post("/api/events", status_code=201)
def ingest_event(event: SecurityEvent):
    event_time = event.timestamp or datetime.now(timezone.utc)

    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    event_time = event_time.astimezone(timezone.utc)
    normalized_time = event_time.isoformat()

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO events (
                event_type, hostname, username, source_ip,
                timestamp, source, raw_event
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event.event_type,
            event.hostname,
            event.username,
            event.source_ip,
            normalized_time,
            event.source,
            event.model_dump_json(),
        ))

        conn.execute("""
            INSERT INTO endpoints (
                hostname, os_name, source, first_seen, last_seen
            )
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                os_name = COALESCE(excluded.os_name, endpoints.os_name),
                source = excluded.source,
                last_seen = excluded.last_seen
        """, (
            event.hostname,
            event.os_name,
            event.source,
            normalized_time,
            normalized_time,
        ))

        alert_created = False

        if (
            event.event_type == "authentication_failure"
            and event.username
        ):
            window_start = (
                event_time - timedelta(
                    minutes=FAILED_LOGIN_WINDOW_MINUTES
                )
            ).isoformat()

            row = conn.execute("""
                SELECT COUNT(*) AS total
                FROM events
                WHERE event_type = 'authentication_failure'
                  AND hostname = ?
                  AND username = ?
                  AND timestamp >= ?
                  AND timestamp <= ?
            """, (
                event.hostname,
                event.username,
                window_start,
                normalized_time,
            )).fetchone()

            failure_count = row["total"]

            if failure_count >= FAILED_LOGIN_THRESHOLD:
                existing = conn.execute("""
                    SELECT id
                    FROM alerts
                    WHERE title = ?
                      AND hostname = ?
                      AND username = ?
                      AND status IN ('New', 'Investigating')
                """, (
                    "Repeated authentication failures",
                    event.hostname,
                    event.username,
                )).fetchone()

                if not existing:
                    conn.execute("""
                        INSERT INTO alerts (
                            id, title, severity, status,
                            hostname, username, source_ip,
                            description, event_count, created_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        str(uuid.uuid4()),
                        "Repeated authentication failures",
                        "High",
                        "New",
                        event.hostname,
                        event.username,
                        event.source_ip,
                        (
                            f"{failure_count} failed authentication "
                            f"events observed for this account on "
                            f"{event.hostname} within "
                            f"{FAILED_LOGIN_WINDOW_MINUTES} minutes. "
                            "Investigate related events and validate "
                            "whether the activity was expected."
                        ),
                        failure_count,
                        datetime.now(timezone.utc).isoformat(),
                    ))

                    alert_created = True

    return {
        "message": "Event received",
        "hostname": event.hostname,
        "event_type": event.event_type,
        "alert_created": alert_created,
    }


# ==================================================
# EVENT SEARCH
# ==================================================

@app.get("/api/events")
def list_events(limit: int = Query(default=100, ge=1, le=500)):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


# ==================================================
# ALERT MANAGEMENT
# ==================================================

@app.get("/api/alerts")
def list_alerts():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM alerts
            ORDER BY created_at DESC
        """).fetchall()

    return [dict(row) for row in rows]


# ==================================================
# ENDPOINT INVENTORY
# ==================================================

@app.get("/api/endpoints")
def list_endpoints():
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT *
            FROM endpoints
            ORDER BY hostname
        """).fetchall()

    return [dict(row) for row in rows]

# ==================================================
# ALERT TRIAGE AND INVESTIGATION
# ==================================================

class AlertUpdate(BaseModel):
    status: Literal["New", "Investigating", "Resolved", "False Positive"] | None = None
    severity: Literal["Critical", "High", "Medium", "Low"] | None = None
    investigation_notes: str | None = Field(default=None, max_length=5000)
    closure_comment: str | None = Field(default=None, max_length=2000)


@app.get("/api/alerts/{alert_id}")
def get_alert_details(alert_id: str):
    with get_connection() as conn:
        alert = conn.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()

        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        related_events = conn.execute(
            """
            SELECT *
            FROM events
            WHERE hostname = ? AND username IS ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (alert["hostname"], alert["username"])
        ).fetchall()

    return {
        "alert": dict(alert),
        "related_events": [dict(event) for event in related_events]
    }


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: str, update: AlertUpdate):
    changes = update.model_dump(exclude_unset=True, exclude_none=True)

    if not changes:
        raise HTTPException(status_code=400, detail="No fields provided")

    with get_connection() as conn:
        existing = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()

        if existing is None:
            raise HTTPException(status_code=404, detail="Alert not found")

        new_status = changes.get("status", existing["status"])
        new_comment = changes.get(
            "closure_comment", existing["closure_comment"]
        )

        if new_status in {"Resolved", "False Positive"}:
            if not new_comment.strip():
                raise HTTPException(
                    status_code=422,
                    detail="Closure comment is required"
                )

        changes["updated_at"] = datetime.now(timezone.utc).isoformat()

        assignments = ", ".join(f"{key} = ?" for key in changes)

        conn.execute(
            f"UPDATE alerts SET {assignments} WHERE id = ?",
            list(changes.values()) + [alert_id]
        )

        updated = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()

    return {
        "message": "Alert updated successfully",
        "alert": dict(updated)
    }

# ============================================================
# SEVERITY-BASED ALERT TRIAGE ENGINE
# ============================================================

def generate_triage(alert: dict) -> dict:
    """
    Generate an initial triage recommendation
    based on alert severity and event details.
    """

    severity = str(alert.get("severity", "Low")).strip().title()
    event_count = int(alert.get("event_count") or 0)
    event_type = str(alert.get("event_type") or "").lower()
    title = str(alert.get("title") or "").lower()

    # Default triage values
    priority_map = {
        "Critical": "P1",
        "High": "P2",
        "Medium": "P3",
        "Low": "P4",
    }

    priority = priority_map.get(severity, "P4")
    escalation_required = severity == "Critical"

    recommended_actions = [
        "Validate the alert against source logs.",
        "Verify the affected hostname and username.",
        "Correlate related events before concluding.",
    ]

    # Additional recommendations for authentication failures
    if "authentication_failure" in event_type or (
        "authentication" in title and "failure" in title
    ):
        recommended_actions.extend([
            "Review failed login timestamps and source IP.",
            "Check for subsequent successful logins.",
            "Determine whether the activity matches expected behavior.",
        ])

        if event_count >= 5:
            recommended_actions.append(
                "Review the repeated failures for possible brute-force activity."
            )

    if severity == "Critical":
        recommended_actions.append(
            "Escalate according to the organization's incident response policy."
        )

    summary = (
        f"{severity} severity alert assigned priority {priority}. "
        f"Observed event count: {event_count}. "
        "Recommendations require analyst validation."
    )

    return {
        "alert_id": alert.get("id"),
        "severity": severity,
        "priority": priority,
        "event_count": event_count,
        "triage_summary": summary,
        "recommended_actions": recommended_actions,
        "escalation_required": escalation_required,
    }


# ============================================================
# TRIAGE API
# ============================================================

@app.get("/api/alerts/{alert_id}/triage")
def triage_alert(alert_id: str):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    alert = dict(row)
    return generate_triage(alert)


# ---------------- MITRE ATT&CK Mapping ----------------

MITRE_TECHNIQUES = {
    "T1110": {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "An attacker may attempt to gain access by repeatedly guessing credentials."
    },
    "T1110.001": {
        "technique_id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "An attacker attempts to access an account by guessing its password."
    },
    "T1078": {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
        "description": "An attacker may use legitimate account credentials to gain access."
    }
}


@app.get("/api/alerts/{alert_id}/mitre")
def get_alert_mitre_mapping(alert_id: str):
    """Return potential MITRE ATT&CK mappings for an alert."""

    conn = get_connection()

    try:
        alert = conn.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()
    finally:
        conn.close()

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_data = dict(alert)

    title = str(alert_data.get("title", "")).lower()
    description = str(alert_data.get("description", "")).lower()

    searchable_text = f"{title} {description}"
    techniques = []

    if "authentication failure" in searchable_text or \
       "authentication failures" in searchable_text or \
       "login failure" in searchable_text or \
       "failed login" in searchable_text or \
       "brute force" in searchable_text:

        techniques.append({
            **MITRE_TECHNIQUES["T1110"],
            "confidence": "Low",
            "mapping_reason": (
                "Repeated authentication failures may be consistent with "
                "brute-force activity. Validate the source and surrounding events."
            )
        })

    if "password guessing" in searchable_text:
        techniques.append({
            **MITRE_TECHNIQUES["T1110.001"],
            "confidence": "Medium",
            "mapping_reason": (
                "The alert text explicitly mentions password guessing."
            )
        })

    if "valid accounts" in searchable_text or \
       "suspicious successful login" in searchable_text:
        techniques.append({
            **MITRE_TECHNIQUES["T1078"],
            "confidence": "Low",
            "mapping_reason": (
                "The alert text suggests potential use of a valid account. "
                "Confirm through authentication logs and investigation."
            )
        })

    return {
        "alert_id": alert_id,
        "alert_title": alert_data.get("title"),
        "mitre_attack": techniques,
        "mapping_count": len(techniques),
        "note": (
            "These are potential rule-based mappings, not proof of attacker "
            "activity. Validate them against the underlying events."
        )
    }




