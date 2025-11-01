#!/usr/bin/env python3
"""
Crear db/mapped.db desde data/events.json
Crea tablas:
 - events: id, host, collected_timestamp, technique_id, technique_name, command, raw_json
 - alerts: id, host, start_time, end_time, chain, status, detected_at
Uso: python3 scripts/create_mapped_db.py
"""
import json
import sqlite3
from pathlib import Path
from dateutil import parser

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "events.json"
DB_DIR = ROOT / "db"
DB = DB_DIR / "mapped.db"

DB_DIR.mkdir(parents=True, exist_ok=True)

def parse_time(ts):
    if not ts:
        return None
    try:
        return parser.isoparse(ts).isoformat()
    except Exception:
        return ts

def ensure_schema(conn):
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT,
        collected_timestamp TEXT,
        technique_id TEXT,
        technique_name TEXT,
        command TEXT,
        raw_json TEXT
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        host TEXT,
        start_time TEXT,
        end_time TEXT,
        chain TEXT,
        status TEXT,
        detected_at TEXT
    );
    """)
    conn.commit()

def load_events(path):
    with open(path, "r", encoding="utf-8") as f:
        docs = json.load(f)
    rows = []
    for d in docs:
        host = d.get("agent_metadata",{}).get("host")
        ts = d.get("collected_timestamp") or d.get("delegated_timestamp") or d.get("finished_timestamp") or d.get("agent_reported_time")
        ts_norm = parse_time(ts)
        tech = None
        tech_name = None
        am = d.get("attack_metadata")
        if isinstance(am, dict):
            tech = am.get("technique_id")
            tech_name = am.get("technique_name")
        cmd = d.get("plaintext_command") or d.get("command")
        raw = json.dumps(d, ensure_ascii=False)
        rows.append((host, ts_norm, tech, tech_name, cmd, raw))
    return rows

def main():
    if not DATA.exists():
        raise SystemExit(f"No se encontró {DATA}. Pon tu events.json en data/")
    conn = sqlite3.connect(str(DB))
    ensure_schema(conn)
    rows = load_events(DATA)
  
    cur = conn.cursor()
    cur.execute("DELETE FROM events;")
    cur.executemany("""
      INSERT INTO events (host, collected_timestamp, technique_id, technique_name, command, raw_json)
      VALUES (?, ?, ?, ?, ?, ?)
    """, rows)
    conn.commit()
    print(f"[+] Insertados {len(rows)} eventos en {DB}")
    conn.close()

if __name__ == "__main__":
    main()
