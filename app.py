import os
import json
import psycopg2
from flask import Flask, request, abort

app = Flask(__name__)

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN")
DATABASE_URL = os.getenv("DATABASE_URL")


def get_db():
    return psycopg2.connect(DATABASE_URL)


@app.route("/webhook", methods=["GET"])
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    print(f"[VERIFY] mode={mode} token={token} challenge={challenge}")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200

    return "forbidden", 403


@app.route("/webhook", methods=["POST"])
def webhook():
    try:
        payload = request.get_json(force=True)
    except Exception:
        print("[ERROR] JSON inválido")
        abort(400, "invalid json")

    print("[WEBHOOK] recebido:", json.dumps(payload))

    try:
        entry = payload.get("entry", [])
        for e in entry:
            for change in e.get("changes", []):
                value = change.get("value", {})
                messages = value.get("messages", [])

                for msg in messages:
                    salvar_mensagem(msg, value)

        return "ok", 200

    except Exception as e:
        print("[DB ERROR]", e)
        abort(500, "db_error")


def salvar_mensagem(msg, value):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            wa_from TEXT,
            msg_type TEXT,
            body TEXT,
            timestamp TEXT
        )
    """)

    cur.execute("""
        INSERT INTO messages (id, wa_from, msg_type, body, timestamp)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (id) DO NOTHING
    """, (
        msg.get("id"),
        msg.get("from"),
        msg.get("type"),
        msg.get("text", {}).get("body"),
        msg.get("timestamp")
    ))

    conn.commit()
    cur.close()
    conn.close()
