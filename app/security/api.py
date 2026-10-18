"""Primary LinkShield API: one check endpoint for anything a person was sent, plus history and preferences."""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from starlette.datastructures import UploadFile

from .orchestrator import ScanInput, scan, scan_upload
from .guard import UnsafeURL
from .identity import account, current_user, google_client_id
from . import engine, storage, telemetry

router = APIRouter(prefix="/api/v1")
_hits = defaultdict(deque)
MAX_UPLOAD_BYTES = int(os.getenv("UPLOAD_MAX_BYTES", str(25 * 1024 * 1024)))
LIMITS = {"check": 40, "speech": 40, "read": 120, "chat": 60}  # per person, per ten minutes (a batch of up to 10 counts as 10 checks)
WINDOW = 600
LANGUAGES = r"^(en|hi|bn|ta|te|mr|gu|kn|ml|pa|ur)$"
LOCALES = {"hi": "hi-IN", "en": "en-IN", "bn": "bn-IN", "ta": "ta-IN", "te": "te-IN", "mr": "mr-IN",
           "gu": "gu-IN", "kn": "kn-IN", "ml": "ml-IN", "pa": "pa-IN", "ur": "ur-IN"}


def throttle(uid: str, bucket: str = "check"):
    """In-memory limit for one server. shared_throttle() is used instead when Firestore is on."""
    now = time.monotonic()
    q = _hits[uid if bucket == "check" else f"{bucket}:{uid}"]
    while q and now-q[0] > WINDOW:
        q.popleft()
    if len(q) >= LIMITS[bucket]:
        raise HTTPException(429, "Scan limit reached. Please try again later.")
    q.append(now)


def shared_throttle(uid: str, bucket: str) -> bool:
    """The same limit kept in Firestore, so it holds across every server instance. Returns False when over the limit."""
    from google.cloud import firestore
    db = storage._db()
    ref = db.collection("linkshield_limits").document(f"{bucket}:{uid}")

    @firestore.transactional
    def take(tx):
        now = time.time()
        hits = [t for t in ((ref.get(transaction=tx).to_dict() or {}).get("hits") or []) if now - t < WINDOW]
        if len(hits) >= LIMITS[bucket]:
            return False
        # expires_at lets a Firestore TTL policy clear idle counters.
        tx.set(ref, {"hits": hits + [now], "expires_at": datetime.now(timezone.utc) + timedelta(seconds=WINDOW * 2)})
        return True
    return take(db.transaction())


async def limit(uid: str, bucket: str = "check"):
    if os.getenv("ENABLE_FIRESTORE", "0") == "1":
        try:
            allowed = await asyncio.to_thread(shared_throttle, uid, bucket)
        except Exception:
            allowed = None  # Firestore trouble must not lock everyone out; fall back to this server's own count.
        if allowed is False:
            raise HTTPException(429, "Scan limit reached. Please try again later.")
        if allowed:
            return
    throttle(uid, bucket)


def _on(name: str) -> bool:
    return bool(os.getenv(name))


@router.get("/capabilities")
async def capabilities():
    google = _on("GOOGLE_CLOUD_PROJECT") and os.getenv("DISABLE_GOOGLE") != "1"
    sandbox = _on("SANDBOX_URL") and _on("SANDBOX_TOKEN")
    return {"demo_mode": os.getenv("AUTH_REQUIRED", "0") != "1", "firestore": os.getenv("ENABLE_FIRESTORE") == "1",
            "gemini_configured": google, "webrisk_configured": google, "claims": google, "speech": google,
            "sandbox_configured": sandbox, "file_scan": sandbox, "max_upload_bytes": MAX_UPLOAD_BYTES,
            "virustotal_configured": _on("VIRUSTOTAL_API_KEY"), "google_client_id": google_client_id(), "chat": google,
            "telegram_bot": os.getenv("TELEGRAM_BOT_USERNAME", "") if _on("TELEGRAM_BOT_TOKEN") else "",
            "whatsapp_bot": os.getenv("WHATSAPP_DISPLAY_NUMBER", "") if _on("WHATSAPP_TOKEN") else "",
            "limitations": "The sandbox observes website behavior and inspects file structure. It does not execute files and is not an antivirus.",
            "firebase_config": {"apiKey":os.getenv("FIREBASE_API_KEY", ""),"authDomain":os.getenv("FIREBASE_AUTH_DOMAIN", ""),
                                "projectId":os.getenv("FIREBASE_PROJECT_ID", ""),"appId":os.getenv("FIREBASE_APP_ID", "")}}


async def finish(uid: str, report: dict, bg: BackgroundTasks) -> dict:
    try:
        await asyncio.to_thread(storage.save, uid, report)
    except Exception:
        # Unavailable history must not turn a valid security scan into a false failed scan.
        report["history_saved"] = False
    else:
        report["history_saved"] = True
    bg.add_task(telemetry.emit, report)
    return report


@router.post("/checks")
async def create_check(request: Request, bg: BackgroundTasks, uid: str = Depends(current_user)):
    """Check anything a person was sent. Multipart fields: text, language, recording, file (all optional, at least one of text/file)."""
    await limit(uid)
    too_big = HTTPException(413, f"Files up to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB can be checked.")
    declared = request.headers.get("content-length", "")
    if not declared.isdigit():
        raise HTTPException(411, "A Content-Length header is required.")
    if int(declared) > MAX_UPLOAD_BYTES + 64 * 1024:
        raise too_big
    attachment = None
    try:
        async with request.form(max_files=1, max_fields=6) as form:
            text, language = form.get("text"), str(form.get("language") or "")
            recording = str(form.get("recording") or "") in ("1", "true")
            upload = form.get("file")
            if isinstance(upload, UploadFile) and upload.filename:
                attachment = (await upload.read(MAX_UPLOAD_BYTES + 1), upload.filename[:200], upload.content_type or "")
    except Exception:
        raise HTTPException(400, "Send the check as a form with text and, optionally, one file.") from None
    if language and language not in engine.SUPPORTED:
        raise HTTPException(422, "Unsupported language.")
    if attachment and len(attachment[0]) > MAX_UPLOAD_BYTES:
        raise too_big
    if attachment and not attachment[0]:
        raise HTTPException(422, "That file is empty.")
    try:
        report = await engine.check(text if isinstance(text, str) else "", language, attachment, recording)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    if report["claims"]:
        from .. import insights
        bg.add_task(insights.log_claims, report["claims"], report["language"])
    return await finish(uid, report, bg)


@router.post("/scans")
async def create_scan(body: ScanInput, bg: BackgroundTasks, uid: str = Depends(current_user)):
    await limit(uid)
    try:
        report = await scan(body)
    except UnsafeURL as exc:
        raise HTTPException(422, str(exc)) from None
    return await finish(uid, report, bg)


@router.post("/files")
async def create_file_scan(request: Request, bg: BackgroundTasks, uid: str = Depends(current_user),
                           x_file_name: str = Header(""), language: str = Query("en", pattern=LANGUAGES)):
    """Inspect a file the user already received. The raw body is the file; it is passed to the sandbox and not kept."""
    await limit(uid)
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Files up to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB can be checked.")
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"Files up to {MAX_UPLOAD_BYTES // (1024 * 1024)} MB can be checked.")
    if not data:
        raise HTTPException(422, "Choose a file to check.")
    report = await scan_upload(bytes(data), unquote(x_file_name)[:200], request.headers.get("content-type", ""), language)
    return await finish(uid, report, bg)


@router.get("/scans")
async def history(uid: str = Depends(current_user)):
    return {"items": await asyncio.to_thread(storage.list_reports, uid)}


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, uid: str = Depends(current_user)):
    result = await asyncio.to_thread(storage.get, uid, scan_id)
    if not result:
        raise HTTPException(404, "Scan was not found")
    return result


@router.get("/scans/{scan_id}/screenshot")
async def get_screenshot(scan_id: str, uid: str = Depends(current_user)):
    data = await asyncio.to_thread(storage.screenshot, uid, scan_id)
    if not data:
        raise HTTPException(404, "No retained screenshot for this scan")
    return Response(data, media_type="image/jpeg", headers={"Cache-Control": "private, no-store"})


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, uid: str = Depends(current_user)):
    await asyncio.to_thread(storage.delete, uid, scan_id)


@router.delete("/scans", status_code=204)
async def clear_history(uid: str = Depends(current_user)):
    await asyncio.to_thread(storage.delete_all, uid)


class Prefs(BaseModel):
    language: str = Field(default="", pattern=r"^(|en|hi|bn|ta|te|mr|gu|kn|ml|pa|ur)$")


@router.get("/me")
async def get_me(who: dict = Depends(account)):
    """Who is signed in, and the preferences remembered for them (or for this guest session)."""
    try:
        prefs = await asyncio.to_thread(storage.get_prefs, who["uid"])
    except Exception:
        prefs = {}
    return {"language": prefs.get("language", ""), "guest": who["guest"], "name": who["name"], "email": who["email"], "picture": who["picture"]}


@router.put("/me")
async def put_me(body: Prefs, uid: str = Depends(current_user)):
    await limit(uid, "read")
    await asyncio.to_thread(storage.set_prefs, uid, body.model_dump())
    return body


# ───────── Report links (sent by the bots) ─────────
# A link names one saved report and is signed, so it cannot be altered to open anyone else's report.
_fallback_secret = secrets.token_hex(32)  # links made with it stop working when this process restarts


def _link_secret() -> bytes:
    return (os.getenv("REPORT_LINK_SECRET") or _fallback_secret).encode()


def report_token(uid: str, scan_id: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps([uid, scan_id], separators=(",", ":")).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(hmac.new(_link_secret(), body.encode(), hashlib.sha256).digest()[:18]).decode()
    return f"{body}.{sig}"


def read_token(token: str) -> tuple[str, str] | None:
    try:
        body, sig = token.split(".", 1)
        good = base64.urlsafe_b64encode(hmac.new(_link_secret(), body.encode(), hashlib.sha256).digest()[:18]).decode()
        if not hmac.compare_digest(sig, good):
            return None
        uid, scan_id = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return str(uid), str(scan_id)
    except Exception:
        return None


def report_link(base_url: str, uid: str, scan_id: str) -> str:
    return f"{base_url.rstrip('/')}/app#r={report_token(uid, scan_id)}"


async def _shared(token: str) -> dict:
    found = read_token(token)
    report = await asyncio.to_thread(storage.get, *found) if found else None
    if not report:
        raise HTTPException(404, "This report link is not valid, or the report was deleted.")
    return report


@router.get("/shared/{token}")
async def open_shared(token: str, uid: str = Depends(current_user)):
    """The full report behind a link a bot sent."""
    await limit(uid, "read")
    return await _shared(token)


@router.post("/shared/{token}/save")
async def save_shared(token: str, bg: BackgroundTasks, uid: str = Depends(current_user)):
    """Keep a report opened from a bot link in this person's own history too."""
    await limit(uid, "read")
    report = await _shared(token)
    if await asyncio.to_thread(storage.get, uid, report["id"]):
        return {"saved": False}
    await asyncio.to_thread(storage.save, uid, report)
    return {"saved": True}


@router.post("/me/claim-guest")
async def claim_guest(who: dict = Depends(account), x_linkshield_session: str | None = Header(None)):
    """Right after signing in: move the checks and Shieldy notes this browser made as a guest into the account."""
    if who["guest"]:
        raise HTTPException(400, "Sign in first.")
    await limit(who["uid"], "read")
    guest = account(None, x_linkshield_session)["uid"]
    moved = await asyncio.to_thread(storage.move_all, guest, who["uid"])
    return {"moved": moved}


class Speech(BaseModel):
    text: str = Field(min_length=1, max_length=1200)
    language: str = Field(default="en", pattern=LANGUAGES)


def synthesize(text: str, language: str) -> bytes:
    from google.cloud import texttospeech as tts
    reply = tts.TextToSpeechClient().synthesize_speech(
        input=tts.SynthesisInput(text=text), voice=tts.VoiceSelectionParams(language_code=LOCALES.get(language, "en-IN")),
        audio_config=tts.AudioConfig(audio_encoding=tts.AudioEncoding.MP3))
    return reply.audio_content


@router.post("/tts")
async def speak(body: Speech, uid: str = Depends(current_user)):
    """Read a verdict aloud. The browser falls back to its own voice when this is not configured."""
    await limit(uid, "speech")
    if not _on("GOOGLE_CLOUD_PROJECT") or os.getenv("DISABLE_GOOGLE") == "1":
        raise HTTPException(503, "Text-to-speech is not configured.")
    try:
        data = await asyncio.to_thread(synthesize, body.text, body.language)
    except Exception:
        raise HTTPException(502, "Text-to-speech is unavailable.") from None
    return Response(data, media_type="audio/mpeg", headers={"Cache-Control": "private, no-store"})


@router.get("/trends")
async def trends(uid: str = Depends(current_user)):
    """Anonymous counts of the most-checked claims. No user ids or web addresses are stored."""
    await limit(uid, "read")
    from .. import insights
    return await asyncio.to_thread(insights.trends)
