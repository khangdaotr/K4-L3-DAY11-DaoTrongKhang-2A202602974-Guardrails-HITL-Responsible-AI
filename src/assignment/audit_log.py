"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input metadata and return the correlation ID used for it."""
        correlation_id = request_id or uuid.uuid4().hex
        self._open[correlation_id] = {
            "request_id": correlation_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_perf": time.perf_counter(),
        }
        return correlation_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Finish an interaction and append a serializable forensic record."""
        correlation_id = request_id
        opened = self._open.pop(correlation_id, None) if correlation_id else None
        if opened is None:
            # Support callers that omit request IDs when only one request for
            # this user is currently open.
            matching_key = next(
                (key for key, value in self._open.items() if value["user_id"] == user_id),
                None,
            )
            if matching_key is not None:
                correlation_id = matching_key
                opened = self._open.pop(matching_key)

        now = time.perf_counter()
        record = {
            "request_id": correlation_id or uuid.uuid4().hex,
            "user_id": user_id,
            "input": opened["input"] if opened else None,
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "started_at": opened["started_at"] if opened else None,
            "completed_at": utc_now_iso(),
            "latency_ms": round(
                ((now - opened["started_perf"]) * 1000) if opened else 0.0,
                3,
            ),
        }
        self.logs.append(record)
        return record

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
