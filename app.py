import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, Response, jsonify
import psycopg

app = Flask(__name__)

# =========================
# Config (Render Env Vars)
# =========================
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")

# Render normalmente usa DATABASE_URL. Você pode ter salvo como DATABASE_URL ou DATABASE_URL (tanto faz aqui).
DATABASE_URL = (
    os.getenv("DATABASE_URL")
    or os.getenv("DATABASE_URL")
    or os.getenv("DB_URL")
    or ""
)

# Durante testes via curl (sem assinatura da Meta), use ALLOW_UNVERIFIED=1
ALLOW_UNVERIFIED = os.getenv("ALLOW_UNVERIFIED", "1") == "1"

# Para testar endpoint rapidamente sem payload WhatsApp
ALLOW_PING = os.getenv("ALLOW_PING", "1") == "1"

# Proteção simples pro /logs (opcional)
LOGS_KEY = os.getenv("LOGS_KEY", "")  # se setar, exige ?key=...


# =========================
# DB helpers + migração
# =========================
def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não configurada")
    return psycopg.connect(DATABASE_URL, autocommit=True)


def ensure_schema():
    """
    Cria tabela e faz migração (adiciona colunas que faltarem).
    Isso resolve o seu erro: column wa_name does not exist.
    """
    with db_conn() as conn:
        with conn.cursor() as cur:
            # 1) Cria tabela base
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    wa_from TEXT,
                    wa_name TEXT,
                    msg_type TEXT,
                    body TEXT,
                    timestamp_wa BIGINT,
                    raw JSONB,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """
            )

            # 2) Migra: adiciona colunas se a tabela foi criada antiga
            cur.execute(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='messages' AND column_name='wa_name'
                    ) THEN
                        ALTER TABLE messages ADD COLUMN wa_name TEXT;
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='messages' AND column_name='raw'
                    ) THEN
                        ALTER TABLE messages ADD COLUMN raw JSONB;
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='messages' AND column_name='timestamp_wa'
                    ) THEN
                        ALTER TABLE messages ADD COLUMN timestamp_wa BIGINT;
                    END IF;

                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name='messages' AND column_name='created_at'
                    ) THEN
                        ALTER TABLE messages ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
                    END IF;
                END $$;
                """
            )

            # 3) Índices úteis (não quebra se já existir)
            cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at DESC);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_wa_from ON messages(wa_from);")


def save_message(msg_id, wa_from, wa_name, msg_type, body, ts, raw_payload):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO messages (id, wa_from, wa_name, msg_type, body, timestamp_wa, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (id) DO NOTHING
                """,
                (msg_id, wa_from, wa_name, msg_type, body, ts, json.dumps(raw_payload)),
            )


# =========================
# Signature verify (Meta)
# =========================
def verify_signature(raw_body: bytes) -> bool:
    """
    Meta manda: X-Hub-Signature-256: sha256=<hmac>
    HMAC = HMAC_SHA256(APP_SECRET, raw_body)
    """
    if not APP_SECRET:
        return False

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not sig or not sig.startswith("sha256="):
        return False

    their_hex = sig.split("sha256=", 1)[1].strip()
    our = hmac.new(APP_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(our, their_hex)


# =========================
# Routes
# =========================
@app.get("/")
def home():
    return "ok", 200


@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    app.logger.info(f"[VERIFY] GET mode={mode} token={token} challenge={challenge}")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return Response(challenge, status=200, mimetype="text/plain")
    return "forbidden", 403


@app.post("/webhook")
def webhook_receive():
    raw = request.get_data() or b""
    # assinatura
    if not verify_signature(raw):
        if not ALLOW_UNVERIFIED:
            return "forbidden", 403

    # JSON parse
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception:
        return "invalid_json", 400

    # ping de teste (não toca no DB)
    if ALLOW_PING and isinstance(payload, dict) and payload.get("ping") == "ok":
        return "ok", 200

    # garante schema antes de salvar
    try:
        ensure_schema()
    except Exception as e:
        app.logger.exception("[DB] erro garantindo schema")
        return "db_error", 500

    # Processa payload do WhatsApp Cloud API
    try:
        entry = (payload.get("entry") or [])
        for e in entry:
            changes = e.get("changes") or []
            for ch in changes:
                value = ch.get("value") or {}
                contacts = value.get("contacts") or []
                wa_name = None
                if contacts:
                    wa_name = ((contacts[0].get("profile") or {}).get("name"))

                messages = value.get("messages") or []
                for m in messages:
                    msg_id = m.get("id")
                    wa_from = m.get("from")
                    ts = m.get("timestamp")
                    msg_type = m.get("type")

                    body = None
                    if msg_type == "text":
                        body = (m.get("text") or {}).get("body")
                    else:
                        # guarda um resumo
                        body = json.dumps(m.get(msg_type, {}), ensure_ascii=False)

                    # fallback pra não quebrar insert
                    msg_id = msg_id or f"noid-{datetime.now(timezone.utc).timestamp()}"
                    ts_int = int(ts) if ts and str(ts).isdigit() else None

                    save_message(
                        msg_id=msg_id,
                        wa_from=wa_from,
                        wa_name=wa_name,
                        msg_type=msg_type,
                        body=body,
                        ts=ts_int,
                        raw_payload=payload,
                    )

    except Exception:
        app.logger.exception("[WEBHOOK] erro processando payload")
        return "process_error", 500

    return "ok", 200


@app.get("/logs")
def logs():
    if LOGS_KEY and request.args.get("key") != LOGS_KEY:
        return "forbidden", 403

    limit = request.args.get("limit", "50")
    try:
        limit = max(1, min(200, int(limit)))
    except Exception:
        limit = 50

    try:
        ensure_schema()
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, wa_from, wa_name, msg_type, body, timestamp_wa, created_at
                    FROM messages
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                rows = cur.fetchall()

        data = []
        for r in rows:
            data.append(
                {
                    "id": r[0],
                    "from": r[1],
                    "name": r[2],
                    "type": r[3],
                    "body": r[4],
                    "timestamp_wa": r[5],
                    "created_at": r[6].isoformat() if r[6] else None,
                }
            )
        return jsonify(data)

    except Exception:
        app.logger.exception("[LOGS] erro lendo DB")
        return "db_error", 500


if __name__ == "__main__":
    # local dev
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
