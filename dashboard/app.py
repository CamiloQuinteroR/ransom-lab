

from flask import Flask, render_template_string, render_template, request, redirect, url_for
import sqlite3
import os
from pathlib import Path
import json

app = Flask(__name__)

TEMPLATE = """

<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Ransomware Detector</title>
    <link href="https://fonts.googleapis.com/css?family=Roboto:400,700&display=swap" rel="stylesheet">
    <style>
        body {
            background: linear-gradient(120deg, #f8fafc 0%, #e0e7ff 100%);
            font-family: 'Roboto', Arial, sans-serif;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 900px;
            margin: 40px auto;
            background: #fff;
            border-radius: 16px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.08);
            padding: 32px 40px 24px 40px;
        }
        h1 {
            color: #4338ca;
            font-size: 2.2rem;
            margin-bottom: 24px;
            text-align: center;
            letter-spacing: 1px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            background: #f3f4f6;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(67,56,202,0.08);
        }
        th, td {
            padding: 12px 10px;
            text-align: left;
        }
        th {
            background: #6366f1;
            color: #fff;
            font-weight: 700;
            border-bottom: 2px solid #4338ca;
        }
        tr {
            transition: background 0.2s;
        }
        tr:nth-child(even) {
            background: #e0e7ff;
        }
        tr:hover {
            background: #c7d2fe;
        }
        .footer {
            text-align: center;
            margin-top: 32px;
            color: #64748b;
            font-size: 0.95rem;
        }
        @media (max-width: 600px) {
            .container {
                padding: 12px 4px;
            }
            table, th, td {
                font-size: 0.95rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🧠 Detecciones Ransomware</h1>
        <table>
            <tr><th>ID</th><th>Archivo</th><th>Operación</th><th>Host</th><th>Secuencia</th><th>Fecha</th><th>Tipo</th></tr>
            {% for d in data %}
            <tr style="background: {% if d[6] == 1 %}#fee2e2{% else %}#e0e7ff{% endif %}; cursor:pointer;" onclick="window.location.href='/details/{{d[0]}}'">
                <td><a href="/details/{{d[0]}}" style="color:inherit;text-decoration:none;">{{d[0]}}</a></td>
                <td>{{d[1]}}</td>
                <td>{{d[2]}}</td>
                <td>{{d[3]}}</td>
                <td style="font-family: monospace; color: #4338ca;">{{d[4]}}</td>
                <td>{{d[5]}}</td>
                <td style="font-weight:bold; color:{% if d[6] == 1 %}#dc2626{% else %}#64748b{% endif %};">
                    {% if d[6] == 1 %}Ataque ransomware{% else %}Falsa alarma{% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
        <div class="footer">
            Proyecto POC MITRE ATT&CK &mdash; <a href="https://attack.mitre.org/" style="color:#6366f1;text-decoration:none;" target="_blank">Referencia MITRE oficial</a>
        </div>
    </div>
</body>
</html>
"""

@app.route("/details/<int:attack_id>")
def details(attack_id):
    db_path = str(Path(__file__).resolve().parent.parent / "db" / "attacks.db")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT file, operation, host FROM attacks WHERE id=?", (attack_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return "No encontrado", 404
    file, operation, host = row
    # Buscar eventos en el archivo correspondiente y operación
    data_dir = Path(__file__).resolve().parent.parent / "data"
    file_path = data_dir / file
    if not file_path.exists():
        conn.close()
        return "Archivo de eventos no encontrado", 404
    with open(file_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    # Extraer técnicas y calcular tiempo entre ellas
    import dateutil.parser
    filtered = [e for e in events if e.get("operation_metadata", {}).get("operation_name") == operation]
    techniques = []
    prev_time = None
    for e in filtered:
        finished = e.get("finished_timestamp")
        delta = None
        if finished:
            t = dateutil.parser.parse(finished)
            if prev_time:
                delta = (t - prev_time).total_seconds()
            prev_time = t
        techniques.append({
            "technique_id": e.get("attack_metadata", {}).get("technique_id", ""),
            "technique_name": e.get("attack_metadata", {}).get("technique_name", ""),
            "command": e.get("command", ""),
            "delta": delta
        })

    conn.close()
    return render_template("details.html", operation=operation, host=host, techniques=techniques)

@app.route("/")
def index():
    # Ruta absoluta para evitar errores de path
    db_path = str(Path(__file__).resolve().parent.parent / "db" / "attacks.db")
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT * FROM attacks")
    data = c.fetchall()
    conn.close()
    return render_template_string(TEMPLATE, data=data)

if __name__ == "__main__":
    app.run(debug=True)
