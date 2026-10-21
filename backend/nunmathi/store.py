"""SQLite-backed analysis store. Captures and results live under NUNMATHI_DATA (default backend/data)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid

DATA = os.path.abspath(os.environ.get("NUNMATHI_DATA", os.path.join(os.path.dirname(__file__), "..", "data")))
CAPTURES = os.path.join(DATA, "captures")
RESULTS = os.path.join(DATA, "results")
_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    os.makedirs(CAPTURES, exist_ok=True)
    os.makedirs(RESULTS, exist_ok=True)
    c = sqlite3.connect(os.path.join(DATA, "nunmathi.db"), timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS analyses (
        id TEXT PRIMARY KEY, name TEXT, source TEXT, created REAL, status TEXT, stage TEXT,
        progress INTEGER, size INTEGER, sha256 TEXT, grade TEXT, score INTEGER, alerts TEXT,
        tunnels INTEGER, error TEXT)""")
    return c


def create(name: str, source: str, size: int, sha256: str) -> str:
    aid = uuid.uuid4().hex[:12]
    with _lock, _conn() as c:
        c.execute("INSERT INTO analyses (id,name,source,created,status,stage,progress,size,sha256) "
                  "VALUES (?,?,?,?,?,?,?,?,?)", (aid, name, source, time.time(), "queued", "queued", 0, size, sha256))
    return aid


def update(aid: str, **kw) -> None:
    if not kw:
        return
    cols = ", ".join(f"{k}=?" for k in kw)
    with _lock, _conn() as c:
        c.execute(f"UPDATE analyses SET {cols} WHERE id=?", (*kw.values(), aid))


def get(aid: str) -> dict | None:
    with _conn() as c:
        r = c.execute("SELECT * FROM analyses WHERE id=?", (aid,)).fetchone()
    return _row(r) if r else None


def list_all() -> list[dict]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM analyses ORDER BY created DESC").fetchall()
    return [_row(r) for r in rows]


def delete(aid: str) -> bool:
    with _lock, _conn() as c:
        n = c.execute("DELETE FROM analyses WHERE id=?", (aid,)).rowcount
    for p in (capture_path(aid), result_path(aid)):
        if os.path.exists(p):
            os.remove(p)
    return n > 0


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["alerts"] = json.loads(d["alerts"]) if d.get("alerts") else None
    return d


def capture_path(aid: str) -> str:
    return os.path.join(CAPTURES, f"{aid}.pcap")


def result_path(aid: str) -> str:
    return os.path.join(RESULTS, f"{aid}.json")


def save_result(aid: str, result: dict) -> None:
    tmp = result_path(aid) + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(result, fh, default=str)
    os.replace(tmp, result_path(aid))


def load_result(aid: str) -> dict | None:
    p = result_path(aid)
    if not os.path.exists(p):
        return None
    with open(p) as fh:
        return json.load(fh)
