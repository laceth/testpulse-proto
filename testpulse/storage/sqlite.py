from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_DB_NAME = "testpulse_history.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_schema(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    schema_path = Path(__file__).with_name("schema.sql")
    schema = schema_path.read_text(encoding="utf-8")
    with _connect(db_path) as conn:
        conn.executescript(schema)
        conn.commit()


def upsert_bundle(db_path: Path, bundle: dict[str, Any]) -> None:
    ensure_schema(db_path)
    run_id = str(bundle.get("run_id", ""))
    if not run_id:
        return
    component_health = bundle.get("metadata", {}).get("component_health_contract", {})
    components = component_health.get("components", []) if isinstance(component_health, dict) else []
    service_metrics = bundle.get("metadata", {}).get("service_metrics", {}).get("metrics", {})
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO runs (run_id, testcase_id, observed_decision, expected_decision, functional_pass, classification, confidence, bundle_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
              testcase_id=excluded.testcase_id,
              observed_decision=excluded.observed_decision,
              expected_decision=excluded.expected_decision,
              functional_pass=excluded.functional_pass,
              classification=excluded.classification,
              confidence=excluded.confidence,
              bundle_json=excluded.bundle_json
            """,
            (
                run_id,
                bundle.get("testcase_id"),
                bundle.get("observed_decision"),
                bundle.get("expected_decision"),
                (None if bundle.get("functional_pass") is None else (1 if bundle.get("functional_pass") else 0)),
                bundle.get("classification"),
                float(bundle.get("confidence", 0.0)),
                json.dumps(bundle),
            ),
        )
        conn.execute("DELETE FROM metrics WHERE run_id=?", (run_id,))
        for key, value in service_metrics.items():
            if isinstance(value, (int, float)):
                conn.execute("INSERT INTO metrics (run_id, metric_key, metric_value) VALUES (?, ?, ?)", (run_id, key, float(value)))
        conn.execute("DELETE FROM component_health WHERE run_id=?", (run_id,))
        for item in components:
            if not isinstance(item, dict):
                continue
            conn.execute(
                "INSERT INTO component_health (run_id, component, status, severity, confidence, finding, recommendation) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    item.get("component"),
                    item.get("status"),
                    item.get("severity"),
                    float(item.get("confidence", 0.0)),
                    item.get("finding"),
                    item.get("recommendation"),
                ),
            )
        conn.commit()


def fetch_runs(
    db_path: Path,
    limit: int = 100,
    search: str | None = None,
    classification: str | None = None,
    outcome: str | None = None,
) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []
    query = (
        "SELECT run_id, testcase_id, observed_decision, expected_decision, functional_pass, "
        "classification, confidence, created_at FROM runs"
    )
    clauses: list[str] = []
    params: list[Any] = []
    if search:
        clauses.append("(run_id LIKE ? OR testcase_id LIKE ?)")
        token = f"%{search}%"
        params.extend([token, token])
    if classification:
        clauses.append("classification = ?")
        params.append(classification)
    if outcome == "pass":
        clauses.append("functional_pass = 1")
    elif outcome == "fail":
        clauses.append("functional_pass = 0")
    if clauses:
        query = f"{query} WHERE {' AND '.join(clauses)}"
    query = f"{query} ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def fetch_bundle(db_path: Path, run_id: str) -> dict[str, Any] | None:
    if not db_path.exists():
        return None
    with _connect(db_path) as conn:
        row = conn.execute("SELECT bundle_json FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if not row:
        return None
    return json.loads(row["bundle_json"])



def fetch_metric_history(
    db_path: Path,
    testcase_id: str | None = None,
    limit: int = 25,
) -> list[dict[str, Any]]:
    if not db_path.exists():
        return []
    query = (
        "SELECT r.run_id, r.testcase_id, r.created_at, m.metric_key, m.metric_value, c.component, c.status, c.severity "
        "FROM runs r "
        "LEFT JOIN metrics m ON m.run_id = r.run_id "
        "LEFT JOIN component_health c ON c.run_id = r.run_id AND ("
        " (m.metric_key = 'dns_lookup_ms' AND c.component = 'dns') OR"
        " (m.metric_key = 'dhcp_ack_packets' AND c.component = 'dhcp') OR"
        " (m.metric_key = 'ldap_bind_ms' AND c.component = 'directory') OR"
        " (m.metric_key = 'coa_ack_ms' AND c.component = 'nas') OR"
        " (m.metric_key = 'ntp_offset_ms' AND c.component = 'ntp')"
        ")"
    )
    params: list[Any] = []
    if testcase_id:
        query += ' WHERE r.testcase_id = ?'
        params.append(testcase_id)
    query += ' ORDER BY r.created_at DESC LIMIT ?'
    params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def fetch_run_created_at(db_path: Path, run_id: str) -> str | None:
    if not db_path.exists():
        return None
    with _connect(db_path) as conn:
        row = conn.execute("SELECT created_at FROM runs WHERE run_id=?", (run_id,)).fetchone()
    if not row:
        return None
    return row['created_at']
