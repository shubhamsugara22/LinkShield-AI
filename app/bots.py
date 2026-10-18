"""Chat bots: forward a suspicious message or file to LinkShield on Telegram or WhatsApp and get the verdict back.

Each webhook proves who is calling (Telegram's secret header, Meta's signed body) before anything is read.
Replies are short: the verdict, one line on why, and a link that opens the full report in the LinkShield app.
Web addresses being checked are defanged, so the bot never hands back a tappable suspicious link; the only
tappable link is to LinkShield's own report. Every bot check is saved to that chat's history.
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os

import httpx
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from .security import engine, storage, telemetry
from .security.api import MAX_UPLOAD_BYTES, limit, report_link

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/bots")
TRANSPORT = None  # replaced in tests
TELEGRAM_MAX_FILE = 20 * 1024 * 1024  # the Bot API will not hand bots anything larger
GRAPH = "https://graph.facebook.com/v21.0"
MARK = {"critical": "🔴 KNOWN THREAT", "high": "🔴 HIGH RISK", "caution": "🟠 CAUTION", "low": "🟢 NO WARNING SIGNS", "unverified": "⚪ NOT VERIFIED"}
# The one-line verdict at the top of a bot reply.
VERDICT = {"critical": "🔴 Known threat: do not open it", "high": "🔴 Dangerous: do not open it", "caution": "🟠 Be careful: some warning signs",
           "low": "🟢 Looks safe: no warning signs found", "unverified": "⚪ Could not check it fully: do not open it yet"}
CLAIM_MARK = {"false": "❌ False", "misleading": "⚠️ Misleading", "true": "✅ True", "unverifiable": "❔ Unverifiable"}
WELCOME = ("LinkShield checks things before you open them.\n\nForward me any suspicious message, link, photo, voice note or file. "
           "I open links in a sandbox, inspect files without running them, fact-check claims, and tell you what to do.\n\n"
           "I am not an antivirus and a clean result is not a guarantee.")
BUSY = "You have sent a lot in the last few minutes. Please try again a little later."
FAILED = "Sorry, that could not be checked just now. Until it is checked, do not open it."


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=30, transport=TRANSPORT)


def short_reply(report: dict, link: str) -> str:
    """The basic answer: the verdict, why in one line, the first thing to do, and the full report link."""
    summary = report["summary"]
    lines = [VERDICT[report["level"]], summary["headline"]]
    if summary.get("next_steps") and report["level"] != "low":
        lines.append(f"👉 {summary['next_steps'][0]}")
    if link:
        lines += ["", f"📄 Full report: {link}"]
    lines.append("A check is not a guarantee of safety.")
    return "\n".join(lines)[:3900]


def format_reply(report: dict) -> str:
    """The whole verdict as plain text, for when no report link can be made."""
    summary = report["summary"]
    lines = [MARK[report["level"]], summary["headline"], "", summary["explanation"]]
    if report["links"]:
        lines += ["", "Links:"] + [f"• {engine.defang(r['domain'])}: {MARK[r['level']].split(' ', 1)[1].title()}" for r in report["links"]]
    if report["uploads"]:
        lines += ["", "Files:"] + [f"• {r['domain']}: {MARK[r['level']].split(' ', 1)[1].title()}" for r in report["uploads"]]
    if report["claims"]:
        lines += ["", "Claims:"]
        for c in report["claims"]:
            lines.append(f"• {CLAIM_MARK.get(c['verdict'], c['verdict'])}: {c['claim']}\n  {c['explanation']}"
                         + (f"\n  Source: {c['sources'][0]['title']}" if c["sources"] else ""))
    if summary["next_steps"]:
        lines += ["", "What to do:"] + [f"{i}. {step}" for i, step in enumerate(summary["next_steps"], 1)]
    lines += ["", "A check is not a guarantee of safety."]
    return "\n".join(lines)[:3900]


async def run_check(uid: str, text: str, attachment, base_url: str = "", source: str = "", contact: str = "") -> tuple[str, str]:
    """Check what was forwarded, save it to the chat's history, and return (reply text, report link).
    source (whatsapp or telegram) and contact (the sender's number or Telegram user id) are saved with it."""
    try:
        await limit(uid)
    except HTTPException:
        return BUSY, ""
    try:
        report = await engine.check(text, "", attachment)
    except ValueError:
        return WELCOME, ""
    except Exception:
        log.exception("bot check failed")
        return FAILED, ""
    try:
        telemetry.emit(report)
    except Exception:
        pass
    link = ""
    try:
        await asyncio.to_thread(storage.save, uid, report, source, contact)
        link = report_link(base_url, uid, report["id"])
    except Exception:
        log.exception("bot check could not be saved")
    return (short_reply(report, link) if link else format_reply(report)), link


def site_url(request: Request) -> str:
    """Where the app lives, for report links: PUBLIC_URL if set, else the address the webhook was called on."""
    url = os.getenv("PUBLIC_URL", "").rstrip("/")
    if url:
        return url
    base = str(request.base_url).rstrip("/")
    return base if base.startswith(("http://localhost", "http://127.0.0.1", "http://testserver")) else "https://" + base.split("://", 1)[-1]


# ───────── Telegram ─────────

class TelegramError(Exception):
    """A failed Bot API call, described without the URL: the URL carries the bot token, which must never reach the logs."""


async def telegram_call(http: httpx.AsyncClient, method: str, **payload):
    reply = await http.post(f"https://api.telegram.org/bot{os.environ['TELEGRAM_BOT_TOKEN']}/{method}", json=payload)
    if reply.is_error:
        try:
            why = reply.json().get("description", "")
        except ValueError:
            why = ""
        raise TelegramError(f"Telegram {method} failed: HTTP {reply.status_code} {why}".strip())
    return reply.json().get("result")


def telegram_attachment(message: dict) -> dict | None:
    """The file part of a Telegram message as {file_id, name, type, size}."""
    for key in ("document", "video", "audio", "voice", "animation", "video_note", "sticker"):
        item = message.get(key)
        if item:
            return {"file_id": item["file_id"], "name": item.get("file_name") or f"{key}.{'ogg' if key == 'voice' else 'bin'}",
                    "type": item.get("mime_type") or ("audio/ogg" if key == "voice" else ""), "size": item.get("file_size") or 0}
    if message.get("photo"):
        best = max(message["photo"], key=lambda p: p.get("file_size") or 0)
        return {"file_id": best["file_id"], "name": "photo.jpg", "type": "image/jpeg", "size": best.get("file_size") or 0}
    return None


async def handle_telegram(update: dict, base_url: str = ""):
    message = update.get("message") or update.get("channel_post") or {}
    chat = (message.get("chat") or {}).get("id")
    if chat is None:
        return
    text = (message.get("text") or message.get("caption") or "").strip()
    found = telegram_attachment(message)
    async with client() as http:
        try:
            if text.split("@")[0] in ("/start", "/help") or (not text and not found):
                await telegram_call(http, "sendMessage", chat_id=chat, text=WELCOME)
                return
            await telegram_call(http, "sendChatAction", chat_id=chat, action="typing")
            attachment, note = None, ""
            if found and found["size"] > min(TELEGRAM_MAX_FILE, MAX_UPLOAD_BYTES):
                note = f"\n\nThe file {found['name']} is too large for me to fetch (limit 20 MB), so it was NOT checked."
            elif found:
                info = await telegram_call(http, "getFile", file_id=found["file_id"])
                got = await http.get(f"https://api.telegram.org/file/bot{os.environ['TELEGRAM_BOT_TOKEN']}/{info['file_path']}")
                if got.is_error:  # the file URL carries the bot token, so the error is described without it
                    raise TelegramError(f"Telegram file download failed: HTTP {got.status_code}")
                attachment = (got.content[:MAX_UPLOAD_BYTES], found["name"], found["type"])
            uid = "tg-" + hashlib.sha256(str(chat).encode()).hexdigest()[:32]
            sender = str((message.get("from") or {}).get("id") or chat)
            reply, link = await run_check(uid, text, attachment, base_url, "telegram", sender) if (text or attachment) else ("Nothing in that message could be checked.", "")
            extra = {"reply_markup": {"inline_keyboard": [[{"text": "📄 Open full report", "url": link}]]}} if link.startswith("https://") else {}
            await telegram_call(http, "sendMessage", chat_id=chat, text=reply + note, link_preview_options={"is_disabled": True},
                                reply_to_message_id=message.get("message_id"), **extra)
        except Exception:
            log.exception("telegram update failed")
            try:
                await telegram_call(http, "sendMessage", chat_id=chat, text=FAILED)
            except Exception:
                pass


@router.post("/telegram")
async def telegram_webhook(request: Request, bg: BackgroundTasks, x_telegram_bot_api_secret_token: str | None = Header(None)):
    secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
    if not os.getenv("TELEGRAM_BOT_TOKEN") or not secret:
        raise HTTPException(404, "Telegram bot is not configured")
    if not hmac.compare_digest(x_telegram_bot_api_secret_token or "", secret):
        raise HTTPException(401, "Unauthorized")
    # Answer straight away; Telegram resends an update that is not acknowledged quickly.
    bg.add_task(handle_telegram, await request.json(), site_url(request))
    return {"ok": True}


# ───────── WhatsApp (Meta Cloud API) ─────────

async def whatsapp_media(http: httpx.AsyncClient, media_id: str) -> bytes:
    auth = {"Authorization": f"Bearer {os.environ['WHATSAPP_TOKEN']}"}
    meta = await http.get(f"{GRAPH}/{media_id}", headers=auth)
    meta.raise_for_status()
    if int(meta.json().get("file_size") or 0) > MAX_UPLOAD_BYTES:
        raise ValueError("too large")
    got = await http.get(meta.json()["url"], headers=auth)
    got.raise_for_status()
    return got.content[:MAX_UPLOAD_BYTES]


async def handle_whatsapp(body: dict, base_url: str = ""):
    async with client() as http:
        for entry in body.get("entry") or []:
            for change in entry.get("changes") or []:
                value = change.get("value") or {}
                phone_id = (value.get("metadata") or {}).get("phone_number_id") or os.getenv("WHATSAPP_PHONE_ID", "")
                for message in value.get("messages") or []:
                    sender, kind = message.get("from"), message.get("type")
                    if not sender or not phone_id:
                        continue
                    try:
                        part = message.get(kind) or {}
                        text = (part.get("body") if kind == "text" else part.get("caption")) or ""
                        attachment, note = None, ""
                        if kind in ("image", "document", "audio", "video", "sticker") and part.get("id"):
                            name = part.get("filename") or {"image": "photo.jpg", "audio": "voice-note.ogg", "video": "video.mp4"}.get(kind, "file.bin")
                            try:
                                attachment = (await whatsapp_media(http, part["id"]), name, part.get("mime_type") or "")
                            except ValueError:
                                note = f"\n\nThe file {name} is too large for me to fetch, so it was NOT checked."
                        uid = "wa-" + hashlib.sha256(sender.encode()).hexdigest()[:32]
                        reply, _ = await run_check(uid, text.strip(), attachment, base_url, "whatsapp", sender) if (text.strip() or attachment) else (WELCOME, "")
                    except Exception:
                        log.exception("whatsapp message failed")
                        reply, note = FAILED, ""
                    try:
                        payload = {"messaging_product": "whatsapp", "to": sender, "type": "text",
                                   "text": {"preview_url": False, "body": (reply + note)[:4000]}}
                        if message.get("id"):
                            payload["context"] = {"message_id": message["id"]}  # shown as a reply to what they sent
                        sent = await http.post(f"{GRAPH}/{phone_id}/messages", headers={"Authorization": f"Bearer {os.environ['WHATSAPP_TOKEN']}"}, json=payload)
                        sent.raise_for_status()
                    except Exception:
                        log.exception("whatsapp reply failed")


@router.get("/whatsapp")
async def whatsapp_verify(mode: str = Query("", alias="hub.mode"), token: str = Query("", alias="hub.verify_token"),
                          challenge: str = Query("", alias="hub.challenge")):
    """Meta calls this once when the webhook is registered."""
    expected = os.getenv("WHATSAPP_VERIFY_TOKEN", "")
    if not expected or mode != "subscribe" or not hmac.compare_digest(token, expected):
        raise HTTPException(403, "Verification failed")
    return PlainTextResponse(challenge)


@router.post("/whatsapp")
async def whatsapp_webhook(request: Request, bg: BackgroundTasks, x_hub_signature_256: str | None = Header(None)):
    secret = os.getenv("WHATSAPP_APP_SECRET", "")
    if not os.getenv("WHATSAPP_TOKEN") or not secret:
        raise HTTPException(404, "WhatsApp bot is not configured")
    raw = await request.body()
    signature = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(x_hub_signature_256 or "", signature):
        raise HTTPException(401, "Unauthorized")
    try:
        body = json.loads(raw)
    except ValueError:
        raise HTTPException(400, "Invalid body") from None
    bg.add_task(handle_whatsapp, body, site_url(request))
    return {"ok": True}
