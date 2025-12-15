import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, Response, jsonify
import psycopg  # psycopg v3

app = Flask(__name__)

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
ALLOW_UNVERIFIED_TEST = os.getenv("ALLOW_UNVERIFIED_TEST", "0").strip() == "1"


def get_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não definido no Render.")
    # No Render geralmente funciona bem assim:
    return psycopg.connect(DATABASE_URL)


def init_db():
    """Cria tabelas e faz 'migração' leve (add colunas faltantes)."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            # Tabela principal de mensagens
            cur.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    wa_from TEXT,
                    wa_name TEXT,
                    msg_type TEXT,
                    body TEXT,
                    ts BIGINT,
                    direction TEXT DEFAULT 'in',
                    raw JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # Migrações (se a tabela já existia com colunas antigas)
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS wa_from TEXT;")
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS wa_name TEXT;")
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS msg_type TEXT;")
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS body TEXT;")
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS ts BIGINT;")
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS direction TEXT DEFAULT 'in';")
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS raw JSONB;")
            cur.execute("ALTER TABLE messages ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();")

            # Eventos que não são mensagens (status, etc.)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS webhook_events (
                    id BIGSERIAL PRIMARY KEY,
                    kind TEXT,
                    raw JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)

            # Index básico pra consulta
            cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(wa_from);")

        conn.commit()


def verify_signature(raw_body: bytes, signature_header: str) -> bool:
    """
    Meta envia: X-Hub-Signature-256: sha256=...
    """
    if not APP_SECRET:
        # Se não tem APP_SECRET configurado, não dá pra validar assinatura.
        return False

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    sent_sig = signature_header.split("=", 1)[1].strip()
    calc_sig = hmac.new(APP_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc_sig, sent_sig)


@app.before_first_request
def startup():
    init_db()


@app.get("/health")
def health():
    return "ok", 200


@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    print(f"[VERIFY] GET mode={mode} token={token} challenge={challenge}")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return Response(challenge, status=200)
    return Response("forbidden", status=403)


@app.post("/webhook")
def webhook_receive():
    raw = request.get_data() or b""
    sig = request.headers.get("X-Hub-Signature-256", "")

    # Se veio assinatura, valida. Se não veio, só permite se ALLOW_UNVERIFIED_TEST=1
    if sig:
        if not verify_signature(raw, sig):
            return Response("forbidden", status=403)
    else:
        if not ALLOW_UNVERIFIED_TEST:
            return Response("forbidden", status=403)

    # Parse JSON
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception:
        print(f"[WEBHOOK] JSON inválido. raw={raw[:200]}")
        return Response("invalid_json", status=400)

    print("[WEBHOOK] body:", json.dumps(payload, ensure_ascii=False)[:1000])

    # Extrai mensagens no formato do WhatsApp Cloud API
    extracted = []

    payload_entry = payload.get("entry", [])
    for entry in payload_entry:
        for change in entry.get("changes", []):
            value = change.get("value", {})
            contacts = value.get("contacts", [])
            messages = value.get("messages", [])

            # tenta pegar nome do contato (quando existir)
            name = None
            wa_id = None
            if contacts:
                prof = (contacts[0].get("profile") or {})
                name = prof.get("name")
                wa_id = contacts[0].get("wa_id")

            for msg in messages:
                msg_id = msg.get("id")
                wa_from = msg.get("from") or wa_id
                ts = msg.get("timestamp")
                msg_type = msg.get("type")

                body = None
                if msg_type == "text":
                    body = (msg.get("text") or {}).get("body")
                else:
                    # guarda algo útil pra outros tipos
                    body = json.dumps(msg.get(msg_type, msg), ensure_ascii=False)

                extracted.append({
                    "id": msg_id or f"no_id_{datetime.now(timezone.utc).timestamp()}",
                    "wa_from": wa_from,
                    "wa_name": name,
                    "msg_type": msg_type,
                    "body": body,
                    "ts": int(ts) if ts and str(ts).isdigit() else None,
                    "direction": "in",
                    "raw": payload
                })

    # Se não tem "messages" (ex: status), salva em webhook_events
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                if extracted:
                    for m in extracted:
                        cur.execute(
                            """
                            INSERT INTO messages (id, wa_from, wa_name, msg_type, body, ts, direction, raw)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT (id) DO NOTHING;
                            """,
                            (m["id"], m["wa_from"], m["wa_name"], m["msg_type"], m["body"], m["ts"], m["direction"], json.dumps(m["raw"]))
                        )
                else:
                    cur.execute(
                        "INSERT INTO webhook_events (kind, raw) VALUES (%s, %s);",
                        ("no_messages", json.dumps(payload))
                    )
            conn.commit()
    except Exception as e:
        print("[DB] erro:", repr(e))
        return Response("db_error", status=500)

    return Response("ok", status=200)


@app.get("/messages")
def list_messages():
    """Só pra você conferir rápido se está gravando."""
    limit = request.args.get("limit", "20")
    try:
        limit_i = max(1, min(200, int(limit)))
    except:
        limit_i = 20

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, wa_from, wa_name, msg_type, body, ts, created_at
                FROM messages
                ORDER BY created_at DESC
                LIMIT %s;
            """, (limit_i,))
            rows = cur.fetchall()

    data = []
    for r in rows:
        data.append({
            "id": r[0],
            "from": r[1],
            "name": r[2],
            "type": r[3],
            "body": r[4],
            "ts": r[5],
            "created_at": r[6].isoformat() if r[6] else None
        })
    return jsonify(data)
