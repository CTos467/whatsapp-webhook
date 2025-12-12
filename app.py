import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, jsonify, Response
import psycopg2
from psycopg2.extras import Json

app = Flask(__name__)

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# ----------------------------
# DB helpers
# ----------------------------
def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não configurada no Render.")
    # Render fornece DATABASE_URL no formato postgres://...
    return psycopg2.connect(DATABASE_URL)

def init_db():
    ddl = """
    CREATE TABLE IF NOT EXISTS wa_events (
      id BIGSERIAL PRIMARY KEY,
      received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      event_type TEXT NOT NULL,            -- 'messages' | 'statuses' | 'unknown'
      wa_id TEXT,                          -- contato (quando existir)
      phone_number_id TEXT,                -- metadata.phone_number_id
      message_id TEXT,                     -- id da mensagem (quando existir)
      status TEXT,                         -- delivered/read/failed/deleted/etc
      from_number TEXT,                    -- messages[].from
      contact_name TEXT,                   -- contacts[].profile.name
      message_type TEXT,                   -- text/image/etc
      message_text TEXT,                   -- texto (quando existir)
      raw JSONB NOT NULL                   -- payload bruto
    );
    CREATE INDEX IF NOT EXISTS idx_wa_events_received_at ON wa_events(received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_wa_events_message_id ON wa_events(message_id);
    """
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(ddl)
        conn.commit()

def insert_event(event_type, wa_id=None, phone_number_id=None, message_id=None,
                 status=None, from_number=None, contact_name=None,
                 message_type=None, message_text=None, raw=None):
    sql = """
    INSERT INTO wa_events
    (event_type, wa_id, phone_number_id, message_id, status, from_number,
     contact_name, message_type, message_text, raw)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (
                event_type,
                wa_id,
                phone_number_id,
                message_id,
                status,
                from_number,
                contact_name,
                message_type,
                message_text,
                Json(raw if raw is not None else {})
            ))
        conn.commit()

# Inicializa tabela ao subir
try:
    init_db()
    app.logger.info("[DB] wa_events OK")
except Exception as e:
    app.logger.error(f"[DB] Falha ao init_db: {e}")

# ----------------------------
# Meta signature verification (X-Hub-Signature-256)
# ----------------------------
def verify_signature(raw_body: bytes) -> bool:
    # Se você não setar APP_SECRET, a assinatura é ignorada (útil pra testar via curl)
    if not APP_SECRET:
        return True

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not sig.startswith("sha256="):
        return False

    received = sig.split("sha256=")[1].strip()
    expected = hmac.new(
        APP_SECRET.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(received, expected)

# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def home():
    return "ok", 200

@app.get("/health")
def health():
    return jsonify({"ok": True}), 200

@app.route("/webhook", methods=["GET"])
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    app.logger.info(f"[VERIFY] GET mode={mode} token={token} challenge={challenge}")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return Response(challenge, status=200, mimetype="text/plain")
    return Response("forbidden", status=403, mimetype="text/plain")

@app.route("/webhook", methods=["POST"])
def webhook_receive():
    raw = request.get_data()  # bytes

    app.logger.info(f"[WEBHOOK] POST recebido {datetime.now(timezone.utc).isoformat()}")
    app.logger.info(f"[WEBHOOK] content-type={request.headers.get('Content-Type')} len={len(raw)}")

    # Verifica assinatura (quando Meta chamar de verdade)
    if not verify_signature(raw):
        app.logger.warning("[WEBHOOK] Assinatura inválida (X-Hub-Signature-256).")
        return Response("forbidden", status=403, mimetype="text/plain")

    # Tenta decodificar JSON
    try:
        payload = request.get_json(force=True, silent=False)
    except Exception:
        app.logger.warning(f"[WEBHOOK] JSON inválido. raw={raw[:200]!r}")
        return Response("bad json", status=400, mimetype="text/plain")

    if not payload:
        app.logger.warning("[WEBHOOK] JSON vazio.")
        return Response("bad json", status=400, mimetype="text/plain")

    # Salva o payload bruto (sempre)
    try:
        insert_event(event_type="raw", raw=payload)
    except Exception as e:
        app.logger.error(f"[DB] Falha ao salvar raw: {e}")

    # Parse WhatsApp payload
    try:
        if payload.get("object") != "whatsapp_business_account":
            app.logger.info(f"[WEBHOOK] objeto inesperado: {payload.get('object')}")
            return "ok", 200

        for entry in payload.get("entry", []):
            for change in entry.get("changes", []):
                field = change.get("field", "unknown")
                value = change.get("value", {}) or {}

                metadata = value.get("metadata", {}) or {}
                phone_number_id = metadata.get("phone_number_id")

                # contatos
                contact_name = None
                wa_id = None
                contacts = value.get("contacts", []) or []
                if contacts:
                    wa_id = contacts[0].get("wa_id")
                    profile = contacts[0].get("profile", {}) or {}
                    contact_name = profile.get("name")

                # mensagens
                messages = value.get("messages", []) or []
                for m in messages:
                    from_number = m.get("from")
                    message_id = m.get("id")
                    mtype = m.get("type")
                    mtext = None
                    if mtype == "text":
                        mtext = (m.get("text") or {}).get("body")

                    insert_event(
                        event_type="messages",
                        wa_id=wa_id,
                        phone_number_id=phone_number_id,
                        message_id=message_id,
                        from_number=from_number,
                        contact_name=contact_name,
                        message_type=mtype,
                        message_text=mtext,
                        raw=payload
                    )
                    app.logger.info(f"[MSG] from={from_number} name={contact_name} type={mtype} id={message_id} text={mtext}")

                # statuses (delivered/read/failed etc)
                statuses = value.get("statuses", []) or []
                for s in statuses:
                    message_id = s.get("id")
                    status = s.get("status")
                    recipient_id = s.get("recipient_id")  # quem recebeu

                    insert_event(
                        event_type="statuses",
                        wa_id=wa_id or recipient_id,
                        phone_number_id=phone_number_id,
                        message_id=message_id,
                        status=status,
                        raw=payload
                    )
                    app.logger.info(f"[STATUS] id={message_id} status={status} recipient={recipient_id}")

        return "ok", 200

    except Exception as e:
        app.logger.error(f"[WEBHOOK] Erro ao processar payload: {e}")
        # Mesmo com erro, é comum devolver 200 pra Meta não ficar reenviando em loop.
        return "ok", 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
