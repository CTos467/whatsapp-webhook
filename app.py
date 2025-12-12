from flask import Flask, request, jsonify

app = Flask(__name__)

VERIFY_TOKEN = "meu_token_whatsapp_2025"

@app.route("/")
def home():
    return "Webhook WhatsApp ativo", 200

@app.route("/webhook", methods=["GET"])
def verify():
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == VERIFY_TOKEN:
        return challenge, 200

    return "Erro de verificação", 403

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json()
    print("Mensagem recebida:", data)
    return jsonify({"status": "ok"}), 200
