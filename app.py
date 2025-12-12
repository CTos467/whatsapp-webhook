import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, abort, Response
import psycopg2
from psycopg2.extras import Json


app = Flask(__name__)

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Se quiser permitir POST de teste via curl sem assinatura (SÓ pra debug),
# defina no Render: ALLOW_UNVERIFIED_TEST=true
ALLOW_UNVERIFIED_TEST = os.getenv("ALLOW_UNVERIFIED_TEST", "false").lower() == "true"


def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não configurada.")
    return psycopg2.connect(DATABASE_URL, sslmode="require")


def ensure_tables():
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS wa_messages (
                    id BIGSERIAL PRIMARY KEY,
                    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    wa_message_id TEXT,
                    wa_from TEXT,
                    wa_name TEXT,
                    wa_type TEXT,
                    wa_text TEXT,
                    timestamp_wa TEXT,
                    phone_number_id TEXT,
                    display_phone_number TEXT,
                    raw_payload JSONB NOT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_wa_messages_wa_from
                ON wa_messages (wa_from);
                """
            )
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_wa_messages_wa_message_id
                ON wa_messages (wa_message_id);
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS wa_events (
                    id BIGSERIAL PRIMARY KEY,
                    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    event_type TEXT,
                    raw_payload JSONB NOT NULL
                );
                """
            )
            conn.commit()


_tables_ready = False


@app.before_request
def _init_once():
    global _tables_ready
    if not _tables_ready and DATABASE_URL:
        ensure_tables()
        _tables_ready = True


def verify_meta_signature(raw_body: bytes) -> bool:
    """
    Meta manda cabeçalho:
      X-Hub-Signature-256: sha256=<hash>
    O hash é HMAC-SHA256 do raw_body usando o APP_SECRET.
    """
    if not APP_SECRET:
        # Se não tiver APP_SECRET, não tem como validar assinatura
        return False

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not sig.startswith("sha256="):
        return False

    their_hash = sig.split("sha256=", 1)[1].strip()
    mac = hmac.new(APP_SECRET.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256)
    our_hash = mac.hexdigest()

    return hmac.compare_digest(our_hash, their_hash)


def store_event(event_type: str, payload: dict):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO wa_events (event_type, raw_payload) VALUES (%s, %s);",
                (event_type, Json(payload)),
            )
            conn.commit()


def store_message(msg: dict, payload: dict, metadata: dict, contact_name: str | None):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO wa_messages
                (wa_message_id, wa_from, wa_name, wa_type, wa_text, timestamp_wa,
                 phone_number_id, display_phone_number, raw_payload)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s);
                """,
                (
                    msg.get("id"),
                    msg.get("from"),
                    contact_name,
                    msg.get("type"),
                    (msg.get("text") or {}).get("body"),
                    msg.get("timestamp"),
                    (metadata or {}).get("phone_number_id"),
                    (metadata or {}).get("display_phone_number"),
                    Json(payload),
                ),
            )
            conn.commit()


@app.get("/")
def home():
    return "ok", 200


@app.get("/health")
def health():
    # Confirma app e DB
    try:
        if DATABASE_URL:
            with db_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1;")
                    _ = cur.fetchone()
        return "healthy", 200
    except Exception as e:
        return f"unhealthy: {e}", 500


@app.get("/webhook")
def webhook_verify():
    # Meta chama isso pra verificar:
    # /webhook?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    print(f"[VERIFY] GET mode={mode} token={token} challenge={challenge}")

    if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
        return Response(challenge, status=200, mimetype="text/plain")
    return Response("forbidden", status=403, mimetype="text/plain")


@app.post("/webhook")
def webhook_post():
    received_at = datetime.now(timezone.utc).isoformat()
    raw = request.get_data(cache=False)  # raw bytes (IMPORTANTE pra assinatura)

    print(f"[WEBHOOK] POST recebido {received_at}")
    # print(f"[WEBHOOK] headers: {dict(request.headers)}")  # se quiser verboso
    print(f"[WEBHOOK] raw_len={len(raw)}")

    # 1) Segurança: validar assinatura Meta
    signed_ok = verify_meta_signature(raw)
    if not signed_ok:
        # Se for só teste manual, você pode habilitar ALLOW_UNVERIFIED_TEST=true
        if not ALLOW_UNVERIFIED_TEST:
            print("[SEC] Assinatura inválida/ausente -> 403")
            return Response("forbidden", status=403, mimetype="text/plain")

    # 2) Parse JSON
    try:
        payload = json.loads(raw.decode("utf-8")) if raw else None
    except Exception:
        payload = None

    if not payload or not isinstance(payload, dict):
        print(f"[WEBHOOK] JSON inválido ou vazio. raw[:40]={raw[:40]!r}")
        return Response("invalid json", status=400, mimetype="text/plain")

    # 3) Se for ping de teste (manual)
    if "ping" in payload:
        store_event("ping", payload)
        print("[PING] salvo no banco.")
        return "ok", 200

    # 4) Evento WhatsApp padrão
    obj = payload.get("object", "")
    if obj != "whatsapp_business_account":
        store_event("unknown_object", payload)
        print(f"[EVENT] objeto diferente: {obj} (salvo em wa_events)")
        return "ok", 200

    # 5) Extrair mensagens (entry -> changes -> value -> messages)
    entries = payload.get("entry", []) or []
    any_saved = 0

    for entry in entries:
        changes = (entry or {}).get("changes", []) or []
        for ch in changes:
            field = (ch or {}).get("field")
            value = (ch or {}).get("value", {}) or {}

            # Salva eventos gerais também (status, etc.)
            if field and field != "messages":
                store_event(field, payload)

            if field != "messages":
                continue

            metadata = value.get("metadata", {}) or {}
            contacts = value.get("contacts", []) or []
            messages = value.get("messages", []) or []

            contact_name = None
            if contacts:
                profile = (contacts[0] or {}).get("profile", {}) or {}
                contact_name = profile.get("name")

            for msg in messages:
                store_message(msg, payload, metadata, contact_name)
                any_saved += 1
                print(
                    f"[MSG] from={msg.get('from')} type={msg.get('type')} id={msg.get('id')}"
                )

    if any_saved == 0:
        # Não veio "messages", mas veio evento válido (status por exemplo)
        store_event("messages_empty", payload)
        print("[EVENT] nenhum msg; payload salvo em wa_events")

    return "ok", 200
