import os
import json
import hmac
import hashlib
from datetime import datetime, timezone

from flask import Flask, request, jsonify, Response
import psycopg

app = Flask(__name__)

VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
ALLOW_UNSIGNED_TESTS = os.getenv("ALLOW_UNSIGNED_TESTS", "false").strip().lower() in ("1", "true", "yes", "y", "on")


# -----------------------
# DB helpers + auto-migrate
# -----------------------
DDL_CREATE = """
CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  wa_from TEXT,
  wa_name TEXT,
  msg_type TEXT,
  body TEXT,
  ts BIGINT,
  raw JSONB,
  direction TEXT DEFAULT 'in',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
"""

DDL_ALTERS = [
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS wa_from TEXT;",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS wa_name TEXT;",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS msg_type TEXT;",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS body TEXT;",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS ts BIGINT;",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS raw JSONB;",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS direction TEXT DEFAULT 'in';",
    "ALTER TABLE messages ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();",
]


def db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não configurada")
    return psycopg.connect(DATABASE_URL, autocommit=True)


def ensure_schema():
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(DDL_CREATE)
            for ddl in DDL_ALTERS:
                cur.execute(ddl)


try:
    if DATABASE_URL:
        ensure_schema()
        app.logger.info("[DB] schema OK")
    else:
        app.logger.warning("[DB] DATABASE_URL vazio (sem banco)")
except Exception as e:
    app.logger.exception("[DB] falha ao garantir schema: %s", e)


# -----------------------
# WhatsApp signature verify
# -----------------------
def verify_signature(raw_body: bytes) -> bool:
    if ALLOW_UNSIGNED_TESTS:
        return True

    if not APP_SECRET:
        app.logger.warning("[SEC] APP_SECRET vazio; bloqueando POST")
        return False

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not sig.startswith("sha256="):
        return False

    their_hex = sig.split("=", 1)[1].strip()
    mac = hmac.new(APP_SECRET.encode("utf-8"), msg=raw_body, digestmod=hashlib.sha256).hexdigest()
    return hmac.compare_digest(their_hex, mac)


def extract_text(message: dict) -> str | None:
    mtype = message.get("type")
    if mtype == "text":
        return (message.get("text") or {}).get("body")
    if mtype == "button":
        return (message.get("button") or {}).get("text")
    if mtype == "interactive":
        inter = message.get("interactive") or {}
        if "list_reply" in inter:
            lr = inter.get("list_reply") or {}
            return lr.get("title") or lr.get("id")
        if "button_reply" in inter:
            br = inter.get("button_reply") or {}
            return br.get("title") or br.get("id")
    return None


def upsert_message(msg_id: str, wa_from: str | None, wa_name: str | None, msg_type: str | None, body: str | None, ts: int | None, raw: dict):
    ensure_schema()
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO messages (id, wa_from, wa_name, msg_type, body, ts, raw, direction)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, 'in')
                ON CONFLICT (id) DO UPDATE SET
                  wa_from = EXCLUDED.wa_from,
                  wa_name = EXCLUDED.wa_name,
                  msg_type = EXCLUDED.msg_type,
                  body = EXCLUDED.body,
                  ts = EXCLUDED.ts,
                  raw = EXCLUDED.raw;
                """,
                (msg_id, wa_from, wa_name, msg_type, body, ts, json.dumps(raw)),
            )


@app.get("/")
def home():
    return "ok", 200


@app.get("/health")
def health():
    return jsonify({"ok": True, "time": datetime.now(timezone.utc).isoformat()}), 200


@app.route("/webhook", methods=["GET"])
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    app.logger.info("[VERIFY] GET mode=%s token=%s challenge=%s", mode, token, challenge)

    if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
        return Response(challenge, status=200, mimetype="text/plain")

    return Response("forbidden", status=403, mimetype="text/plain")


@app.route("/webhook", methods=["POST"])
def webhook_receive():
    raw = request.get_data() or b""
    app.logger.info("[WEBHOOK] POST recebido %s", datetime.now(timezone.utc).isoformat())
    app.logger.info("[WEBHOOK] UA=%s len=%s", request.headers.get("User-Agent", ""), len(raw))

    if not verify_signature(raw):
        return Response("forbidden", status=403, mimetype="text/plain")

    try:
        payload = request.get_json(force=True, silent=False)
    except Exception:
        app.logger.warning("[WEBHOOK] JSON inválido. raw=%r", raw[:200])
        return Response("invalid json", status=400, mimetype="text/plain")

    try:
        entries = payload.get("entry") or []
        for entry in entries:
            changes = entry.get("changes") or []
            for ch in changes:
                value = ch.get("value") or {}
                contacts = value.get("contacts") or []
                wa_name = None
                wa_from_contact = None
                if contacts:
                    wa_name = (contacts[0].get("profile") or {}).get("name")
                    wa_from_contact = contacts[0].get("wa_id")

                messages = value.get("messages") or []
                for msg in messages:
                    msg_id = msg.get("id") or f"no-id-{int(datetime.now(timezone.utc).timestamp()*1000)}"
                    wa_from = msg.get("from") or wa_from_contact
                    msg_type = msg.get("type")
                    body = extract_text(msg)

                    ts = None
                    try:
                        ts = int(msg.get("timestamp")) if msg.get("timestamp") else None
                    except Exception:
                        ts = None

                    upsert_message(
                        msg_id=msg_id,
                        wa_from=wa_from,
                        wa_name=wa_name,
                        msg_type=msg_type,
                        body=body,
                        ts=ts,
                        raw=payload,
                    )

                    app.logger.info("[MSG] id=%s from=%s name=%s type=%s body=%s", msg_id, wa_from, wa_name, msg_type, (body or "")[:80])

    except Exception as e:
        app.logger.exception("[WEBHOOK] erro salvando no banco: %s", e)
        return Response("db_error", status=500, mimetype="text/plain")

    return Response("ok", status=200, mimetype="text/plain")


@app.get("/messages")
def list_messages():
    limit = request.args.get("limit", "50")
    try:
        limit_i = max(1, min(500, int(limit)))
    except Exception:
        limit_i = 50

    try:
        ensure_schema()
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, wa_from, wa_name, msg_type, body, ts, created_at
                    FROM messages
                    ORDER BY created_at DESC
                    LIMIT %s;
                    """,
                    (limit_i,),
                )
                rows = cur.fetchall()
    except Exception as e:
        app.logger.exception("[MESSAGES] erro lendo banco: %s", e)
        return jsonify({"ok": False, "error": "db_error"}), 500

    out = []
    for (mid, wa_from, wa_name, msg_type, body, ts, created_at) in rows:
        out.append(
            {
                "id": mid,
                "from": wa_from,
                "name": wa_name,
                "type": msg_type,
                "body": body,
                "ts": ts,
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
            }
        )
    return jsonify({"ok": True, "count": len(out), "messages": out}), 200


if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
