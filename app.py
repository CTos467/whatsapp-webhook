import os
import json
import hmac
import hashlib
import logging
from datetime import datetime, timezone

from flask import Flask, request, abort, Response
import psycopg2
import psycopg2.extras


# --------------------------
# Config / Logging
# --------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("whatsapp-webhook")

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL", "") or os.getenv("DATABASE_URL".lower(), "")
ALLOW_UNVERIFIED_TEST = os.getenv("ALLOW_UNVERIFIED_TEST", "false").lower() in ("1", "true", "yes", "y")


def _normalize_db_url(url: str) -> str:
    # Render costuma fornecer algo tipo postgres://... (psycopg2 aceita),
    # e às vezes sem sslmode. Vamos garantir sslmode=require.
    if not url:
        return url
    if "sslmode=" not in url:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}sslmode=require"
    return url


DB_DSN = _normalize_db_url(DATABASE_URL)


# --------------------------
# DB Helpers
# --------------------------
def db_connect():
    if not DB_DSN:
        raise RuntimeError("DATABASE_URL não está definida no Render.")
    return psycopg2.connect(DB_DSN)


def db_init():
    # cria tabela se não existir
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS wa_messages (
                    id BIGSERIAL PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    source TEXT NOT NULL,
                    from_wa TEXT NULL,
                    wa_id TEXT NULL,
                    msg_id TEXT NULL,
                    msg_type TEXT NULL,
                    text_body TEXT NULL,
                    raw JSONB NOT NULL
                );
                """
            )
        conn.commit()
    log.info("[DB] Tabela wa_messages OK")


def db_insert(source: str, payload: dict, from_wa=None, wa_id=None, msg_id=None, msg_type=None, text_body=None):
    with db_connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO wa_messages (source, from_wa, wa_id, msg_id, msg_type, text_body, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (source, from_wa, wa_id, msg_id, msg_type, text_body, json.dumps(payload)),
            )
        conn.commit()


# --------------------------
# Signature validation (Meta)
# --------------------------
def verify_meta_signature(raw_body: bytes) -> bool:
    """
    Meta envia header: X-Hub-Signature-256: sha256=<hex>
    """
    if not APP_SECRET:
        log.warning("[SIG] APP_SECRET vazio. Assinatura não pode ser validada.")
        return False

    header = request.headers.get("X-Hub-Signature-256", "")
    if not header.startswith("sha256="):
        log.warning("[SIG] Header X-Hub-Signature-256 ausente ou inválido.")
        return False

    received = header.split("=", 1)[1].strip()
    expected = hmac.new(APP_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    ok = hmac.compare_digest(received, expected)

    if not ok:
        log.warning("[SIG] Assinatura inválida.")
    return ok


# --------------------------
# Flask app
# --------------------------
app = Flask(__name__)

# inicializa DB no boot
try:
    db_init()
except Exception as e:
    log.exception("[DB] Falha ao inicializar o banco: %s", e)


@app.get("/")
def health():
    return "ok", 200


@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    log.info("[VERIFY] GET mode=%s token=%s challenge=%s", mode, token, challenge)

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return Response(challenge, status=200, mimetype="text/plain")
    return "forbidden", 403


@app.post("/webhook")
def webhook_receive():
    raw = request.get_data() or b""
    now = datetime.now(timezone.utc).isoformat()

    try:
        payload = request.get_json(silent=True)
    except Exception:
        payload = None

    log.info("[WEBHOOK] POST %s len=%s", now, len(raw))

    # 1) caminho de teste (curl)
    if payload and isinstance(payload, dict) and payload.get("ping") == "ok":
        if not ALLOW_UNVERIFIED_TEST:
            return "forbidden", 403
        try:
            db_insert("ping_test", payload, msg_type="ping", text_body="ok")
            log.info("[PING] salvo no banco.")
            return "ok", 200
        except Exception as e:
            log.exception("[PING] erro ao gravar no banco: %s", e)
            return "db_error", 500

    # 2) eventos reais da Meta (precisa validar assinatura)
    if not verify_meta_signature(raw):
        return "forbidden", 403

    if not payload:
        log.warning("[WEBHOOK] JSON inválido ou vazio. raw=%r", raw[:200])
        return "invalid json", 400

    # grava payload bruto (sempre)
    try:
        db_insert("meta_raw", payload)
    except Exception as e:
        log.exception("[DB] erro ao gravar payload bruto: %s", e)
        # mesmo falhando, devolve 200 para não gerar retentativas infinitas
        return "ok", 200

    # tenta extrair mensagens
    try:
        entry = payload.get("entry", [])
        for e in entry:
            changes = e.get("changes", [])
            for ch in changes:
                value = ch.get("value", {})
                contacts = value.get("contacts", [])
                messages = value.get("messages", [])

                name = None
                wa_id = None
                if contacts:
                    prof = contacts[0].get("profile", {})
                    name = prof.get("name")
                    wa_id = contacts[0].get("wa_id")

                for m in messages:
                    frm = m.get("from")
                    msg_id = m.get("id")
                    msg_type = m.get("type")
                    text_body = None
                    if msg_type == "text":
                        text_body = (m.get("text") or {}).get("body")

                    row = {
                        "name": name,
                        "wa_id": wa_id,
                        "message": m,
                        "value": value,
                    }

                    db_insert(
                        "meta_message",
                        row,
                        from_wa=frm,
                        wa_id=wa_id,
                        msg_id=msg_id,
                        msg_type=msg_type,
                        text_body=text_body,
                    )

                    log.info("[MSG] from=%s name=%s type=%s text=%r", frm, name, msg_type, text_body)

    except Exception as e:
        log.exception("[PARSE] erro ao processar mensagem: %s", e)

    return "ok", 200
