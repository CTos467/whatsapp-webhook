import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, jsonify, abort
import psycopg

app = Flask(__name__)

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("DATABASE_URL".replace("_", ""))  # tolerância


def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não configurada")
    # Render Postgres usa SSL; psycopg3 aceita sslmode=require
    return psycopg.connect(DATABASE_URL, sslmode="require")


def init_db():
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
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
            """)
        conn.commit()


def verify_signature(raw_body: bytes) -> bool:
    """
    Verifica X-Hub-Signature-256: sha256=<hmac>
    """
    # Se você estiver testando via curl, não tem assinatura.
    # Em produção real do WhatsApp, vai ter.
    sig = request.headers.get("X-Hub-Signature-256", "")
    if not sig:
        return False

    if not sig.startswith("sha256="):
        return False

    their_hash = sig.split("=", 1)[1].strip()
    mac = hmac.new(APP_SECRET.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256)
    our_hash = mac.hexdigest()
    return hmac.compare_digest(our_hash, their_hash)


@app.get("/health")
def health():
    return "ok", 200


@app.route("/webhook", methods=["GET"])
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    app.logger.info(f"[VERIFY] GET mode={mode} token={token} challenge={challenge}")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200
    return "forbidden", 403


@app.route("/webhook", methods=["POST"])
def webhook_receive():
    raw = request.get_data()  # bytes
    if not raw:
        return "empty", 400

    # Se for WhatsApp real, valide assinatura
    # (Você pode permitir curl sem assinatura quando quiser testar)
    allow_unsigned = os.getenv("ALLOW_UNSIGNED_TESTS", "false").lower() == "true"

    if APP_SECRET:
        ok_sig = verify_signature(raw)
        if not ok_sig and not allow_unsigned:
            app.logger.warning("[WEBHOOK] assinatura inválida/ausente -> 403")
            return "forbidden", 403

    # Parse JSON
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        app.logger.exception("[WEBHOOK] JSON inválido")
        return "invalid json", 400

    # Log básico
    app.logger.info("[WEBHOOK] POST recebido")

    # Extrair mensagens no formato do WhatsApp Cloud API
    # payload["entry"][i]["changes"][j]["value"]["messages"][k]
    try:
        entries = payload.get("entry", [])
        saved = 0

        with get_db() as conn:
            with conn.cursor() as cur:
                for entry in entries:
                    changes = entry.get("changes", [])
                    for ch in changes:
                        value = ch.get("value", {})
                        contacts = value.get("contacts", [])
                        name = None
                        if contacts:
                            name = contacts[0].get("profile", {}).get("name")

                        messages = value.get("messages", [])
                        for m in messages:
                            msg_id = m.get("id")
                            wa_from = m.get("from")
                            msg_type = m.get("type")
                            ts = m.get("timestamp")
                            ts_int = int(ts) if ts and str(ts).isdigit() else None

                            body = None
                            if msg_type == "text":
                                body = (m.get("text") or {}).get("body")
                            elif msg_type == "button":
                                body = (m.get("button") or {}).get("text")
                            elif msg_type == "interactive":
                                # pode ser reply em lista/botão
                                body = json.dumps(m.get("interactive"), ensure_ascii=False)
                            else:
                                # salva algo útil do payload inteiro do msg
                                body = json.dumps(m, ensure_ascii=False)

                            if not msg_id:
                                # evita quebrar; gera id fallback
                                msg_id = f"noid_{wa_from}_{datetime.now(timezone.utc).timestamp()}"

                            cur.execute(
                                """
                                INSERT INTO messages (id, wa_from, wa_name, msg_type, body, timestamp_wa, raw)
                                VALUES (%s, %s, %s, %s, %s, %s, %s)
                                ON CONFLICT (id) DO NOTHING;
                                """,
                                (msg_id, wa_from, name, msg_type, body, ts_int, json.dumps(payload))
                            )
                            saved += 1

            conn.commit()

        return "ok", 200

    except Exception:
        app.logger.exception("[WEBHOOK] erro salvando no banco")
        return "db_error", 500


@app.get("/messages")
def list_messages():
    """
    Lista as últimas 50 mensagens salvas.
    """
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, wa_from, wa_name, msg_type, body, created_at
                    FROM messages
                    ORDER BY created_at DESC
                    LIMIT 50;
                """)
                rows = cur.fetchall()

        out = []
        for r in rows:
            out.append({
                "id": r[0],
                "from": r[1],
                "name": r[2],
                "type": r[3],
                "body": r[4],
                "created_at": r[5].isoformat() if r[5] else None,
            })
        return jsonify(out), 200
    except Exception:
        app.logger.exception("[MESSAGES] erro lendo banco")
        return jsonify({"error": "db_error"}), 500


# Inicializa tabela ao subir (clássico e simples)
try:
    init_db()
except Exception:
    # não derruba o app se DB estiver momentaneamente fora
    app.logger.exception("Falha ao inicializar DB na subida")
