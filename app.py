import os
import json
import hmac
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# =========================
# CONFIGURAÇÕES
# =========================
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "meu_token_whatsapp_2025")
APP_SECRET = os.getenv("APP_SECRET", "")  # opcional por enquanto

# =========================
# WEBHOOK
# =========================
@app.route("/webhook", methods=["GET", "POST"])
def webhook():
    if request.method == "GET":
        return verify_webhook()

    if request.method == "POST":
        return handle_webhook()

    return "Método não permitido", 405


# =========================
# VERIFICAÇÃO (GET)
# =========================
def verify_webhook():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    print("[VERIFY] GET:", {
        "mode": mode,
        "token": token,
        "challenge": challenge
    })

    if mode == "subscribe" and token == VERIFY_TOKEN:
        print("[VERIFY] Token OK")
        return challenge, 200

    print("[VERIFY] Token inválido")
    return "Token inválido", 403


# =========================
# RECEBIMENTO (POST)
# =========================
def handle_webhook():
    print(f"[WEBHOOK] POST recebido {datetime.utcnow().isoformat()}")

    raw_data = request.data
    headers = dict(request.headers)

    print("[WEBHOOK] headers:", headers)

    if not raw_data:
        print("[WEBHOOK] Body vazio")
        return "ok", 200  # Meta exige 200

    try:
        payload = json.loads(raw_data)
    except json.JSONDecodeError:
        print("[WEBHOOK] JSON inválido:", raw_data)
        return "invalid json", 400

    print("[WEBHOOK] body:", json.dumps(payload, indent=2))

    # Processa mensagens
    process_messages(payload)

    return "ok", 200


# =========================
# PROCESSAMENTO DAS MENSAGENS
# =========================
def process_messages(payload):
    if payload.get("object") != "whatsapp_business_account":
        return

    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})

            messages = value.get("messages", [])
            contacts = value.get("contacts", [])

            contact_name = None
            if contacts:
                contact_name = contacts[0].get("profile", {}).get("name")

            for msg in messages:
                message_data = {
                    "from": msg.get("from"),
                    "name": contact_name,
                    "type": msg.get("type"),
                    "id": msg.get("id"),
                    "text": None
                }

                if msg.get("type") == "text":
                    message_data["text"] = msg.get("text", {}).get("body")

                print("[MSG]", message_data)

                # 🔹 Aqui você pode:
                # - salvar no banco
                # - responder via API
                # - jogar num queue
                # - chamar outro serviço


# =========================
# HEALTHCHECK
# =========================
@app.route("/")
def health():
    return "Webhook WhatsApp rodando", 200


# =========================
# START
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
