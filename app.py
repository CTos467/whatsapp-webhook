import os
import json
import time
import hashlib
from datetime import datetime, timezone
from flask import Flask, request, abort

app = Flask(__name__)

# =========================
# Config
# =========================
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "meu_token_whatsapp_2025")  # deve bater com o que você digita no Meta
APP_SECRET = os.getenv("APP_SECRET", "")  # opcional (assinatura X-Hub-Signature-256). Se vazio, não valida.
TZ = timezone.utc

# Dedup simples em memória (no Free do Render pode reiniciar; é OK para começar)
SEEN_CACHE = {}  # key -> last_seen_ts
SEEN_TTL_SECONDS = 60 * 60  # 1h


# =========================
# Helpers
# =========================
def log(*args):
    print(*args, flush=True)


def now_iso():
    return datetime.now(TZ).isoformat()


def _prune_seen():
    cutoff = time.time() - SEEN_TTL_SECONDS
    for k, ts in list(SEEN_CACHE.items()):
        if ts < cutoff:
            del SEEN_CACHE[k]


def seen_before(key: str) -> bool:
    _prune_seen()
    if key in SEEN_CACHE:
        return True
    SEEN_CACHE[key] = time.time()
    return False


def verify_signature(raw_body: bytes) -> bool:
    """
    Valida assinatura HMAC SHA256 enviada pela Meta em X-Hub-Signature-256.
    Só funciona se APP_SECRET estiver definido.
    """
    if not APP_SECRET:
        return True  # sem secret, não valida (modo simples)

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not sig.startswith("sha256="):
        return False

    received = sig.split("=", 1)[1].strip()
    mac = hashlib.new("sha256", raw_body, key=APP_SECRET.encode("utf-8"))  # errado, hashlib não usa key assim
    return False


# Versão correta de HMAC:
import hmac
def verify_signature(raw_body: bytes) -> bool:
    if not APP_SECRET:
        return True

    sig = request.headers.get("X-Hub-Signature-256", "")
    if not sig.startswith("sha256="):
        return False

    received = sig.split("=", 1)[1].strip()
    expected = hmac.new(APP_SECRET.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(received, expected)


def extract_messages(payload: dict):
    """
    Extrai mensagens do formato WhatsApp Cloud API (webhooks).
    Retorna lista de dicts "normalizados".
    """
    out = []

    entry = payload.get("entry", [])
    for e in entry:
        changes = e.get("changes", [])
        for ch in changes:
            value = ch.get("value", {})
            metadata = value.get("metadata", {}) or {}
            phone_number_id = metadata.get("phone_number_id")
            display_phone_number = metadata.get("display_phone_number")

            # Mensagens recebidas
            messages = value.get("messages", []) or []
            contacts = value.get("contacts", []) or []

            # Nome do contato (quando vem)
            contact_name = None
            wa_id = None
            if contacts:
                wa_id = contacts[0].get("wa_id")
                profile = contacts[0].get("profile", {}) or {}
                contact_name = profile.get("name")

            for msg in messages:
                msg_id = msg.get("id")
                from_wa = msg.get("from")  # número do cliente (wa_id)
                ts = msg.get("timestamp")
                mtype = msg.get("type")

                text = ""
                if mtype == "text":
                    text = (msg.get("text", {}) or {}).get("body", "")
                elif mtype == "button":
                    text = (msg.get("button", {}) or {}).get("text", "")
                elif mtype == "interactive":
                    inter = msg.get("interactive", {}) or {}
                    # pode ser list_reply / button_reply
                    if "list_reply" in inter:
                        text = (inter["list_reply"] or {}).get("title", "")
                    elif "button_reply" in inter:
                        text = (inter["button_reply"] or {}).get("title", "")
                else:
                    # midia: image/audio/video/document/sticker/location/etc.
                    text = f"[{mtype}]"

                out.append({
                    "received_at": now_iso(),
                    "direction": "recebida",
                    "from_wa": from_wa or wa_id,
                    "contact_name": contact_name,
                    "to_phone_number_id": phone_number_id,
                    "to_display_phone": display_phone_number,
                    "message_id": msg_id,
                    "timestamp": ts,
                    "type": mtype,
                    "text": text,
                    "raw": msg
                })

            # Status (enviada/entregue/lida) — opcional
            statuses = value.get("statuses", []) or []
            for st in statuses:
                out.append({
                    "received_at": now_iso(),
                    "direction": "status",
                    "status": st.get("status"),
                    "message_id": st.get("id"),
                    "recipient_id": st.get("recipient_id"),
                    "timestamp": st.get("timestamp"),
                    "raw": st
                })

    return out


# =========================
# Routes
# =========================
@app.get("/")
def health():
    log("[HEALTH]", request.method, request.path, now_iso())
    return "ok", 200


@app.get("/webhook")
def webhook_verify():
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    log("[VERIFY] query:", dict(request.args))
    log("[VERIFY] expected:", VERIFY_TOKEN)

    if mode == "subscribe" and token == VERIFY_TOKEN:
        log("[VERIFY] OK -> returning challenge:", challenge)
        return challenge, 200

    log("[VERIFY] FAIL -> token inválido")
    return "Token inválido", 403


@app.post("/webhook")
def webhook_receive():
    raw = request.get_data()  # bytes
    if not verify_signature(raw):
        log("[WEBHOOK] assinatura inválida!")
        return "invalid signature", 403

    payload = request.get_json(silent=True)
    log("[WEBHOOK] POST recebido", now_iso())
    log("[WEBHOOK] headers:", dict(request.headers))

    if payload is None:
        log("[WEBHOOK] JSON inválido ou vazio. raw:", raw[:500])
        return "bad request", 400

    log("[WEBHOOK] body:", json.dumps(payload, ensure_ascii=False)[:4000])

    # Extrair e normalizar mensagens
    events = extract_messages(payload)

    if not events:
        log("[WEBHOOK] sem eventos de mensagem/status no payload.")
        return "ok", 200

    for ev in events:
        # Dedup por message_id quando existir
        mid = ev.get("message_id")
        if mid and seen_before(mid):
            log("[DEDUP] ignorando repetida:", mid)
            continue

        # Aqui é onde você vai mandar pro Google Sheets / DB depois.
        # Por enquanto, logamos bonito:
        if ev.get("direction") == "recebida":
            log("[MSG]", {
                "from": ev.get("from_wa"),
                "name": ev.get("contact_name"),
                "type": ev.get("type"),
                "text": ev.get("text"),
                "id": ev.get("message_id"),
            })
        else:
            log("[STATUS]", {
                "status": ev.get("status"),
                "id": ev.get("message_id"),
                "to": ev.get("recipient_id"),
            })

    return "ok", 200
