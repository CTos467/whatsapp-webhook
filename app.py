import os
import json
from datetime import datetime, timezone

from flask import Flask, request, Response

app = Flask(__name__)

def log(*args):
    print(*args, flush=True)

VERIFY_TOKEN = (os.getenv("VERIFY_TOKEN") or "").strip()

@app.get("/")
def home():
    return "ok", 200

@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = (request.args.get("hub.verify_token", "") or "").strip()
    challenge = request.args.get("hub.challenge", "")

    log("[VERIFY] GET /webhook",
        {"mode": mode, "token_received": token, "challenge": challenge, "has_env_token": bool(VERIFY_TOKEN)})

    if mode == "subscribe" and token and token == VERIFY_TOKEN:
        log("[VERIFY] OK - returning challenge")
        return Response(challenge, status=200, mimetype="text/plain")

    # Se você está vendo "forbidden", cai aqui.
    log("[VERIFY] FORBIDDEN",
        {"expected_env_token": VERIFY_TOKEN, "received": token, "mode": mode})
    return Response("forbidden", status=403, mimetype="text/plain")


@app.post("/webhook")
def webhook_receive():
    now = datetime.now(timezone.utc).isoformat()
    log(f"[WEBHOOK] POST recebido {now}")

    raw = request.get_data(cache=False) or b""
    if not raw:
        log("[WEBHOOK] body vazio")
        return "empty", 400

    try:
        body = request.get_json(force=True, silent=False)
    except Exception as e:
        log("[WEBHOOK] JSON inválido:", repr(e), "raw:", raw[:200])
        return "invalid json", 400

    log("[WEBHOOK] body:", json.dumps(body, ensure_ascii=False)[:2000])

    # Extrai mensagens (quando vier do WhatsApp Cloud API)
    try:
        entry0 = (body.get("entry") or [])[0]
        change0 = (entry0.get("changes") or [])[0]
        value = change0.get("value") or {}
        messages = value.get("messages") or []
        contacts = value.get("contacts") or []
        name = ""
        if contacts and contacts[0].get("profile"):
            name = contacts[0]["profile"].get("name", "")

        for m in messages:
            msg_type = m.get("type")
            text = ""
            if msg_type == "text":
                text = (m.get("text") or {}).get("body", "")
            log("[MSG]", {
                "from": m.get("from"),
                "name": name,
                "type": msg_type,
                "text": text,
                "id": m.get("id"),
            })
    except Exception as e:
        log("[WEBHOOK] Falha ao extrair mensagens:", repr(e))

    return "ok", 200
