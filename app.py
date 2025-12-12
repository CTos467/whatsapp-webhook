import os
import json
from datetime import datetime, timezone
from flask import Flask, request, Response

app = Flask(__name__)

# ===== Config via ENV =====
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "")  # o mesmo que você colocou no Meta (ex: 777 ou "meu_token_whatsapp_2025")
LOG_PATH = os.getenv("LOG_PATH", "messages.jsonl")  # arquivo onde vamos gravar tudo (append)
DEBUG_LOG = os.getenv("DEBUG_LOG", "1") == "1"      # 1 = loga bastante, 0 = mais silencioso


# ===== Helpers =====
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def log(*args):
    if DEBUG_LOG:
        print(*args, flush=True)

def append_jsonl(obj: dict, path: str = LOG_PATH):
    # Grava 1 JSON por linha (padrão bom para auditoria)
    line = json.dumps(obj, ensure_ascii=False)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


# ===== Rotas =====
@app.get("/")
def health():
    return "ok", 200

@app.get("/webhook")
def webhook_verify():
    """
    Meta verifica assim:
      GET /webhook?hub.mode=subscribe&hub.verify_token=SEU_TOKEN&hub.challenge=777
    Você NÃO "coloca" hub.challenge em lugar nenhum: a Meta manda.
    Seu servidor precisa devolver o challenge (texto puro) se o token bater.
    """
    mode = request.args.get("hub.mode", "")
    token = request.args.get("hub.verify_token", "")
    challenge = request.args.get("hub.challenge", "")

    log(f"[VERIFY] GET mode={mode} token={token} challenge={challenge}")

    if mode == "subscribe" and token and token == VERIFY_TOKEN:
        # devolve exatamente o challenge
        return Response(challenge, status=200, mimetype="text/plain")
    return Response("forbidden", status=403, mimetype="text/plain")


@app.post("/webhook")
def webhook_receive():
    """
    Recebe eventos do WhatsApp Cloud API e também pode receber pings seus (curl).
    Sempre responde 200 rápido (importante).
    """
    ts = now_iso()

    raw = request.get_data(cache=False) or b""
    ua = request.headers.get("User-Agent", "")
    ct = request.headers.get("Content-Type", "")

    log(f"[WEBHOOK] POST recebido {ts}")
    log(f"[WEBHOOK] UA={ua} CT={ct} bytes={len(raw)}")

    # Tenta parsear JSON
    try:
        body = request.get_json(silent=True)
    except Exception:
        body = None

    if not body:
        # Se veio ping seu e deu ruim por escape/aspas, logamos raw e devolvemos 400
        log(f"[WEBHOOK] JSON inválido ou vazio. raw: {raw[:200]!r}")
        append_jsonl({
            "ts": ts,
            "kind": "invalid_json",
            "headers": {"user-agent": ua, "content-type": ct},
            "raw_preview": raw[:200].decode("utf-8", errors="replace")
        })
        return Response("bad json", status=400, mimetype="text/plain")

    # Sempre salva o payload bruto (audit trail)
    append_jsonl({
        "ts": ts,
        "kind": "raw_event",
        "body": body
    })

    # Se for seu ping
    if "ping" in body or "test" in body:
        append_jsonl({
            "ts": ts,
            "kind": "ping",
            "body": body
        })
        return Response("ok", status=200, mimetype="text/plain")

    # Se for evento padrão da Meta (whatsapp_business_account)
    obj = body.get("object")
    entry = body.get("entry", [])

    if obj != "whatsapp_business_account":
        append_jsonl({
            "ts": ts,
            "kind": "unknown_object",
            "object": obj,
            "body": body
        })
        return Response("ok", status=200, mimetype="text/plain")

    # Extrai mensagens (quando vier "field": "messages")
    extracted = []
    try:
        for e in entry:
            changes = e.get("changes", [])
            for ch in changes:
                field = ch.get("field")
                value = ch.get("value", {})

                if field != "messages":
                    continue

                metadata = value.get("metadata", {})
                display_phone = metadata.get("display_phone_number")
                phone_number_id = metadata.get("phone_number_id")

                contacts = value.get("contacts", [])
                messages = value.get("messages", [])

                # nome do contato (se vier)
                contact_name = None
                wa_id = None
                if contacts:
                    contact_name = safe_get(contacts[0], "profile", "name")
                    wa_id = safe_get(contacts[0], "wa_id")

                for m in messages:
                    m_type = m.get("type")
                    m_from = m.get("from")
                    m_id = m.get("id")
                    m_ts = m.get("timestamp")  # epoch string

                    text_body = None
                    if m_type == "text":
                        text_body = safe_get(m, "text", "body")

                    item = {
                        "ts": ts,
                        "kind": "message",
                        "to_business_display_phone": display_phone,
                        "phone_number_id": phone_number_id,
                        "from": m_from,
                        "wa_id": wa_id,
                        "name": contact_name,
                        "type": m_type,
                        "text": text_body,
                        "message_id": m_id,
                        "message_timestamp": m_ts,
                        "raw_message": m,
                    }
                    extracted.append(item)

    except Exception as ex:
        log(f"[ERR] Falha extraindo mensagens: {ex}")
        append_jsonl({
            "ts": ts,
            "kind": "extract_error",
            "error": str(ex),
            "body": body
        })
        return Response("ok", status=200, mimetype="text/plain")

    # Salva cada msg extraída como uma linha também (mais fácil filtrar depois)
    for item in extracted:
        append_jsonl(item)
        log("[MSG]", {k: item[k] for k in ("from", "name", "type", "text", "message_id")})

    return Response("ok", status=200, mimetype="text/plain")


if __name__ == "__main__":
    # Local: python app.py
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
