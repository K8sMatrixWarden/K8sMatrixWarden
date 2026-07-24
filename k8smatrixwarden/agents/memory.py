"""
Persistent agent memory (Phase 2 + 3), plain SQLite, stdlib only.

Three tables the agent reads/writes across investigations, assets, findings, lessons, plus a
small tool_quality log (Phase 5). No vector DB, no ORM: keyword search is a LIKE scan, which is
plenty at this scale and keeps the core dependency-free.

`search_memory` / `prelude_for` retrieve only RELEVANT rows (by asset + keyword), never the whole
store, so injected context stays small (Phase 3).
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from datetime import datetime, timezone

DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".k8smatrixwarden")
DEFAULT_PATH = os.environ.get("K8SMATRIXWARDEN_MEMORY_DB",
                              os.path.join(DEFAULT_DIR, "agent_memory.db"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
  asset_id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname TEXT UNIQUE, ip TEXT, services TEXT,
  first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset TEXT, finding TEXT, severity TEXT, evidence TEXT,
  status TEXT, timestamp TEXT,
  confidence REAL, verification_status TEXT, evidence_json TEXT);
CREATE TABLE IF NOT EXISTS lessons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT, successful_tool_sequence TEXT, failure_reason TEXT,
  lesson TEXT, timestamp TEXT);
CREATE TABLE IF NOT EXISTS tool_quality (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tool TEXT, quality_score REAL, missing_information TEXT,
  recommended_followup TEXT, timestamp TEXT);
"""

_STOP = {"the", "and", "for", "with", "this", "that", "check", "scan", "find", "from",
         "into", "machine", "server", "host", "investigate", "any", "are", "was"}
_HOST = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}|[a-z][a-z0-9\-]*\d[a-z0-9\-]*)\b", re.I)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _keywords(text: str) -> list[str]:
    return [w for w in set(re.findall(r"[a-z0-9][a-z0-9\-]{2,}", (text or "").lower()))
            if w not in _STOP][:8]


def extract_asset(text: str):
    """First hostname-with-a-digit (server01) or IPv4 in the text, else None."""
    m = _HOST.search(text or "")
    return m.group(1) if m else None


class Memory:
    def __init__(self, path: str = DEFAULT_PATH):
        if path != ":memory:" and os.path.dirname(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        self._migrate()
        self.db.commit()

    def _migrate(self) -> None:
        """Add Upgrade-3 finding columns to a pre-existing DB (CREATE IF NOT EXISTS won't)."""
        have = {r["name"] for r in self.db.execute("PRAGMA table_info(findings)")}
        for col, typ in (("confidence", "REAL"), ("verification_status", "TEXT"),
                         ("evidence_json", "TEXT")):
            if col not in have:
                self.db.execute(f"ALTER TABLE findings ADD COLUMN {col} {typ}")

    # -- assets ----------------------------------------------------------- #
    def upsert_asset(self, hostname: str, ip=None, services=None) -> None:
        row = self.db.execute("SELECT * FROM assets WHERE hostname=?", (hostname,)).fetchone()
        now = _now()
        merged = sorted(set(services or []))
        if row:
            existing = set(json.loads(row["services"] or "[]"))
            # Never wipe known services when called without new ones (e.g. from save_finding).
            merged = sorted(existing | set(services)) if services else sorted(existing)
            self.db.execute(
                "UPDATE assets SET ip=COALESCE(?,ip), services=?, last_seen=? WHERE hostname=?",
                (ip, json.dumps(merged), now, hostname))
        else:
            self.db.execute(
                "INSERT INTO assets(hostname,ip,services,first_seen,last_seen) VALUES(?,?,?,?,?)",
                (hostname, ip, json.dumps(merged), now, now))
        self.db.commit()

    # -- findings --------------------------------------------------------- #
    def save_finding(self, asset, finding, severity="INFO", evidence="", status="open",
                     confidence=None, verification_status=None, evidence_items=None) -> None:
        self.db.execute(
            "INSERT INTO findings(asset,finding,severity,evidence,status,timestamp,"
            "confidence,verification_status,evidence_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (asset, finding, severity, evidence, status, _now(),
             confidence, verification_status, json.dumps(evidence_items or [])))
        self.db.commit()
        if asset:
            self.upsert_asset(asset)

    def get_asset_history(self, hostname: str) -> dict:
        a = self.db.execute("SELECT * FROM assets WHERE hostname=?", (hostname,)).fetchone()
        f = self.db.execute("SELECT * FROM findings WHERE asset=? ORDER BY id DESC",
                            (hostname,)).fetchall()
        return {"asset": dict(a) if a else None,
                "services": json.loads(a["services"]) if a and a["services"] else [],
                "findings": [dict(r) for r in f]}

    # -- lessons ---------------------------------------------------------- #
    def save_lesson(self, task, successful_tool_sequence=None, lesson="",
                    failure_reason=None) -> None:
        self.db.execute(
            "INSERT INTO lessons(task,successful_tool_sequence,failure_reason,lesson,timestamp) "
            "VALUES(?,?,?,?,?)",
            (task, json.dumps(successful_tool_sequence or []), failure_reason, lesson, _now()))
        self.db.commit()

    # -- tool quality (Phase 5) ------------------------------------------- #
    def save_tool_quality(self, tool, quality_score, missing_information="",
                          recommended_followup="") -> None:
        self.db.execute(
            "INSERT INTO tool_quality(tool,quality_score,missing_information,"
            "recommended_followup,timestamp) VALUES(?,?,?,?,?)",
            (tool, quality_score, missing_information, recommended_followup, _now()))
        self.db.commit()

    def tool_quality_hints(self, limit: int = 20) -> str:
        """Aggregate past tool-quality observations into an injectable hint block (Upgrade 2),
        so the LLM learns which tools usually come back thin without which follow-ups."""
        rows = self.db.execute(
            "SELECT tool, AVG(quality_score) AS s, GROUP_CONCAT(missing_information) AS miss "
            "FROM tool_quality GROUP BY tool ORDER BY s ASC LIMIT ?", (limit,)).fetchall()
        lines = []
        for r in rows:
            if r["s"] is None or r["s"] >= 1.0:
                continue
            miss = sorted({m.strip() for m in (r["miss"] or "").split(",") if m.strip()})
            note = ("usually incomplete without: " + ", ".join(miss) if miss
                    else f"often low quality (avg {r['s']:.2f})")
            lines.append(f"  {r['tool']}: {note}")
        return "Previous tool-quality observations:\n" + "\n".join(lines) if lines else ""

    # -- retrieval -------------------------------------------------------- #
    def search_memory(self, query: str, limit: int = 5) -> dict:
        """Relevant findings + lessons by keyword LIKE. Only matching rows, never the store."""
        terms = _keywords(query)
        findings, lessons = [], []
        if terms:
            fwhere = " OR ".join(["finding LIKE ? OR evidence LIKE ? OR asset LIKE ?"] * len(terms))
            fparams = [f"%{t}%" for t in terms for _ in range(3)]
            findings = [dict(r) for r in self.db.execute(
                f"SELECT * FROM findings WHERE {fwhere} ORDER BY id DESC LIMIT ?",
                (*fparams, limit))]
            lwhere = " OR ".join(["task LIKE ? OR lesson LIKE ?"] * len(terms))
            lparams = [f"%{t}%" for t in terms for _ in range(2)]
            lessons = [dict(r) for r in self.db.execute(
                f"SELECT * FROM lessons WHERE {lwhere} ORDER BY id DESC LIMIT ?",
                (*lparams, limit))]
        return {"findings": findings, "lessons": lessons}

    def prelude_for(self, query: str, limit: int = 5) -> str:
        """Format the relevant-context block injected before an investigation (Phase 3)."""
        parts: list[str] = []
        host = extract_asset(query)
        if host:
            h = self.get_asset_history(host)
            if h["services"]:
                parts.append(f"Known services on {host}: " + ", ".join(h["services"]))
            if h["findings"]:
                parts.append(f"Recent findings on {host}:")
                for f in h["findings"][:limit]:
                    parts.append(f"  - [{f['severity']}] {f['finding']} (status: {f['status']})")
        hits = self.search_memory(query, limit=limit)
        if not host:
            for f in hits["findings"][:limit]:
                parts.append(f"Prior finding: [{f['severity']}] {f['finding']} on {f['asset']}")
        for lesson in hits["lessons"][:limit]:
            seq = " -> ".join(json.loads(lesson["successful_tool_sequence"] or "[]"))
            note = lesson["lesson"] or lesson["failure_reason"] or ""
            line = f"Prior investigation pattern ({lesson['task']}): {seq}"
            parts.append(line + (f", {note}" if note else ""))
        if not parts:
            return ""
        return "Relevant prior context (from agent memory):\n" + "\n".join(parts)

    def close(self) -> None:
        self.db.close()
