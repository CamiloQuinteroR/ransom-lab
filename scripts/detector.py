import json, sqlite3, os
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
DB_PATH = str(ROOT / "db" / "mapped.db")
ATTACKS_DB_PATH = str(ROOT / "db" / "attacks.db")
DATA_PATH = str(ROOT / "data" / "events.json")

# Secuencia ransomware: descubrimiento → colección → exfiltración → impacto
RANSOM_SEQUENCE = ["T1083", "T1005", "T1041", "T1486"]


def init_attacks_db():
    os.makedirs(ROOT / "db", exist_ok=True)
    conn = sqlite3.connect(ATTACKS_DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file TEXT,
        operation TEXT,
        host TEXT,
        sequence TEXT,
        detected_at TEXT,
        is_attack INTEGER
    )''')
    conn.commit()
    return conn


def detect_sequences(events):
    events_by_op = {}
    for e in events:
        op = e["operation_metadata"]["operation_name"]
        events_by_op.setdefault(op, []).append(e)

    alerts = []
    for op, ops_events in events_by_op.items():
        seq = [ev["attack_metadata"]["technique_id"] for ev in ops_events]
        unique_seq = set(seq)
      
        if sum(t in unique_seq for t in RANSOM_SEQUENCE) >= 3:
            host = ops_events[0]["agent_metadata"]["host"]
            alerts.append((op, host, ",".join(seq), ops_events[-1]["finished_timestamp"]))
    return alerts



def main():
    attacks_conn = init_attacks_db()
    data_dir = Path(__file__).resolve().parent.parent / "data"
    json_files = list(data_dir.glob("*.json"))
    total_attacks = 0
    for json_file in json_files:
        with open(json_file, "r", encoding="utf-8") as f:
            events = json.load(f)
        detections = detect_sequences(events)
        if not detections:
            print(f"⚠️ No se detectaron secuencias ransomware en {json_file.name}.")
            # Registrar falsa alarma en la base de datos
            if events:
                # Registrar cada operación como falsa alarma
                events_by_op = {}
                for e in events:
                    op = e["operation_metadata"]["operation_name"]
                    events_by_op.setdefault(op, []).append(e)
                for op, ops_events in events_by_op.items():
                    host = ops_events[0]["agent_metadata"]["host"]
                    seq = ",".join([ev["attack_metadata"]["technique_id"] for ev in ops_events])
                    time = ops_events[-1]["finished_timestamp"]
                    attacks_conn.execute("INSERT INTO attacks (file, operation, host, sequence, detected_at, is_attack) VALUES (?,?,?,?,?,?)",
                        (json_file.name, op, host, seq, time, 0))
        else:
            print(f"✅ Se detectaron {len(detections)} posibles ataques en {json_file.name}:")
            for op, host, seq, time in detections:
                print(f" - {op} ({host}) → {seq}")
                attacks_conn.execute("INSERT INTO attacks (file, operation, host, sequence, detected_at, is_attack) VALUES (?,?,?,?,?,?)",
                    (json_file.name, op, host, seq, time, 1))
                total_attacks += 1
    attacks_conn.commit()
    print(f"[+] Total de ataques detectados: {total_attacks}")
    attacks_conn.close()

if __name__ == "__main__":
    main()
