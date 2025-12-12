from flask import Flask, request
import os, json, sys, time

app = Flask(__name__)

def log(*args):
    print(*args, flush=True)

@app.get("/")
def health():
    log("HEALTH HIT", request.method, request.path)
    return "ok", 200

@app.get("/webhook")
def verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")
    log("VERIFY GET:", {"mode": mode, "token": token, "challenge": challenge})
    # se quiser travar por token, compare com env VERIFY_TOKEN
    expected = os.getenv("VERIFY_TOKEN", "777")
    if mode == "subscribe" and token == expected:
        return challenge, 200
    return "forbidden", 403

@app.post("/webhook")
def webhook():
    data = request.get_json(silent=True)
    log("=== INCOMING WEBHOOK POST ===")
    log("Headers:", dict(request.headers))
    log("Body:", json.dumps(data, ensure_ascii=False) if data else data)
    return "ok", 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
