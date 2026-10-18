"""Per-person check history, preferences and Shieldy notes, plus optional private Cloud Storage screenshots.

Where it lives, first match wins:
- Firestore when ENABLE_FIRESTORE=1;
- BigQuery when BQ_DATASET is set (e.g. my-project.linkshield): tables `history` and `profiles`;
- otherwise this server's memory, which a restart wipes.

With BigQuery, memory is a cache in front of it: a person's history is read from BigQuery once per server
process, and every save or delete is sent to BigQuery as a DML job. The server waits only for BigQuery to
accept the job, not for it to finish, so a check is not slowed down. DML (not streaming inserts) is used so
that a deletion takes effect at once. Screenshots are never stored in BigQuery.
"""
import base64
import collections
import json
import logging
import os
import threading
from datetime import datetime, timezone

log = logging.getLogger("linkshield.storage")

_mem = collections.defaultdict(lambda: collections.OrderedDict())


def _db():
    if os.getenv("ENABLE_FIRESTORE", "0") != "1":
        return None
    from google.cloud import firestore
    return firestore.Client(project=os.getenv("GOOGLE_CLOUD_PROJECT"))


def _doc(db, uid, scan_id):
    return db.collection("linkshield_users").document(uid).collection("scans").document(scan_id)


def compact(report):
    """Drop screenshots before a report is kept: they can show personal data from the page."""
    def strip(item):
        sandbox = item.get("sandbox") or {}
        return {**item, "sandbox": {**sandbox, "evidence": {k: v for k, v in (sandbox.get("evidence") or {}).items() if k != "screenshot_base64"}}}
    if report.get("kind") == "check":
        return {**report, "links": [strip(x) for x in report.get("links", [])], "uploads": [strip(x) for x in report.get("uploads", [])]}
    return strip(report)


# ───────── BigQuery ─────────
_bq_conn = None  # the BigQuery client, made on first use
_loaded: set[str] = set()  # people whose history this process has already read from BigQuery
_lock = threading.Lock()
MAX_HISTORY = 30


def _dataset() -> str:
    return "" if _db() else os.getenv("BQ_DATASET", "")


def _bq_client():
    global _bq_conn
    if _bq_conn is None:
        from google.cloud import bigquery
        _bq_conn = bigquery.Client(project=os.getenv("GOOGLE_CLOUD_PROJECT"))
    return _bq_conn


def _bq(sql: str, wait: bool = False, **params):
    """Run one parameterised query. Without wait, return once BigQuery has accepted the job."""
    from google.cloud import bigquery
    types = {str: "STRING", int: "INT64"}
    cfg = bigquery.QueryJobConfig(query_parameters=[bigquery.ScalarQueryParameter(k, types[type(v)], v) for k, v in params.items()])
    job = _bq_client().query(sql.replace("{ds}", _dataset()), job_config=cfg, location=os.getenv("BQ_LOCATION", "asia-south1"))
    return list(job.result(timeout=20)) if wait else job


def _ensure_loaded(uid: str):
    """Read a person's history from BigQuery the first time this process needs it, keeping newer local saves."""
    if not _dataset() or uid in _loaded:
        return
    with _lock:
        if uid in _loaded:
            return
        try:
            rows = _bq("SELECT report FROM `{ds}.history` WHERE uid = @uid ORDER BY created_at DESC LIMIT %d" % MAX_HISTORY, wait=True, uid=uid)
            stored = collections.OrderedDict((r["id"], r) for r in (json.loads(row.report) for row in reversed(rows)))
            stored.update(_mem[uid])  # anything saved here while the read ran is newer
            _mem[uid] = collections.OrderedDict(list(stored.items())[-MAX_HISTORY:])
        except Exception:
            log.exception("could not read history from BigQuery")
        _loaded.add(uid)


# ───────── Preferences and notes (one profile per person) ─────────
_profiles: dict = {}
PROFILE_FIELDS = ("prefs", "chat_notes")


def _profile(uid: str) -> dict:
    if uid not in _profiles and _dataset():
        try:
            # Two saves at the same moment can each add a row, so take the newest value of every field across rows.
            rows = _bq("""SELECT ARRAY_AGG(prefs IGNORE NULLS ORDER BY updated_at DESC LIMIT 1)[SAFE_OFFSET(0)] AS prefs,
                                 ARRAY_AGG(chat_notes IGNORE NULLS ORDER BY updated_at DESC LIMIT 1)[SAFE_OFFSET(0)] AS chat_notes
                          FROM `{ds}.profiles` WHERE uid = @uid GROUP BY uid""", wait=True, uid=uid)
            _profiles[uid] = {f: json.loads(getattr(rows[0], f) or "null") for f in PROFILE_FIELDS} if rows else {}
        except Exception:
            log.exception("could not read profile from BigQuery")
            return {}
    return _profiles.setdefault(uid, {})


def get_field(uid: str, field: str, default=None):
    db = _db()
    if db:
        snap = db.collection("linkshield_users").document(uid).get()
        value = (snap.to_dict() or {}).get(field) if snap.exists else None
    else:
        value = _profile(uid).get(field)
    return default if value is None else value


def set_field(uid: str, field: str, value):
    assert field in PROFILE_FIELDS
    db = _db()
    if db:
        db.collection("linkshield_users").document(uid).set({field: value}, merge=True)
        return value
    _profile(uid)[field] = value
    if _dataset():
        try:
            _bq(f"""MERGE `{{ds}}.profiles` t USING (SELECT @uid AS uid) s ON t.uid = s.uid
                    WHEN MATCHED THEN UPDATE SET {field} = @v, updated_at = CURRENT_TIMESTAMP()
                    WHEN NOT MATCHED THEN INSERT (uid, {field}, updated_at) VALUES (@uid, @v, CURRENT_TIMESTAMP())""",
                uid=uid, v=json.dumps(value, ensure_ascii=False))
        except Exception:
            log.exception("could not save profile to BigQuery")
    return value


def get_prefs(uid: str) -> dict:
    return dict(get_field(uid, "prefs", {}))


def set_prefs(uid: str, prefs: dict) -> dict:
    return set_field(uid, "prefs", dict(prefs))


def _blob(uid: str, scan_id: str):
    bucket = os.getenv("EVIDENCE_BUCKET", "")
    if not bucket:
        return None
    from google.cloud import storage
    return storage.Client().bucket(bucket).blob(f"scans/{uid}/{scan_id}.jpg")


def save(uid: str, report: dict, source: str = "website", contact: str = ""):
    """Keep a report in this person's history. source is where the check came from (website, whatsapp or telegram);
    contact is who sent it on a bot: their WhatsApp number or Telegram user id."""
    snapshot_b64 = (report.get("sandbox", {}).get("evidence", {}) or {}).get("screenshot_base64")
    obj = compact(report)
    if snapshot_b64 and os.getenv("EVIDENCE_BUCKET"):
        raw = base64.b64decode(snapshot_b64, validate=True)
        if len(raw) < 350_000 and raw.startswith(b"\xff\xd8"):
            blob = _blob(uid, report["id"])
            blob.upload_from_string(raw, content_type="image/jpeg")
            obj["sandbox"]["evidence"]["screenshot_saved"] = True
    db = _db()
    if db:
        _doc(db, uid, report["id"]).set({"created_at": datetime.now(timezone.utc), "report": obj, "source": source, "contact": contact or None})
    else:
        _ensure_loaded(uid)
        history = _mem[uid]
        history[report["id"]] = obj
        while len(history) > MAX_HISTORY:
            history.popitem(last=False)
        if _dataset():
            text = json.dumps(obj, ensure_ascii=False, default=str)
            if len(text) > 900_000:  # BigQuery's limit for query parameters; keep the verdict, drop the bulky evidence
                text = json.dumps({k: obj.get(k) for k in ("id", "kind", "label", "level", "score", "summary", "language", "domain", "url", "target")}, default=str)
            _bq("""INSERT `{ds}.history` (uid, scan_id, created_at, kind, level, score, label, report, source, contact)
                   VALUES (@uid, @id, CURRENT_TIMESTAMP(), @kind, @level, @score, @label, @report, @source, NULLIF(@contact, ''))""",
                uid=uid, id=str(report["id"]), source=source, contact=str(contact or ""), kind=str(obj.get("kind") or obj.get("target") or "scan"), level=str(obj.get("level") or ""),
                score=int(obj.get("score") or 0), label=str(obj.get("label") or obj.get("domain") or "")[:200], report=text)


def list_reports(uid: str) -> list[dict]:
    db = _db()
    if db:
        docs = db.collection("linkshield_users").document(uid).collection("scans").order_by("created_at", direction="DESCENDING").limit(30).stream()
        return [d.to_dict()["report"] for d in docs]
    _ensure_loaded(uid)
    return list(reversed(list(_mem[uid].values())))


def get(uid: str, scan_id: str):
    db = _db()
    if db:
        snap = _doc(db, uid, scan_id).get()
        return snap.to_dict()["report"] if snap.exists else None
    _ensure_loaded(uid)
    return _mem[uid].get(scan_id)


def screenshot(uid: str, scan_id: str) -> bytes | None:
    report = get(uid, scan_id)
    if not report or not (report.get("sandbox") or {}).get("evidence", {}).get("screenshot_saved"):
        return None
    blob = _blob(uid, scan_id)
    if not blob:
        return None
    return blob.download_as_bytes()


def delete(uid: str, scan_id: str):
    report = get(uid, scan_id)
    if report and (report.get("sandbox") or {}).get("evidence", {}).get("screenshot_saved"):
        try:
            _blob(uid, scan_id).delete()
        except Exception:
            pass  # One-day bucket lifecycle remains a fallback.
    db = _db()
    if db:
        _doc(db, uid, scan_id).delete()
    else:
        _mem[uid].pop(scan_id, None)
        if _dataset():
            _bq("DELETE `{ds}.history` WHERE uid = @uid AND scan_id = @id", uid=uid, id=scan_id)


def delete_all(uid: str):
    if _dataset() and not _db():
        for report in list_reports(uid):
            if (report.get("sandbox") or {}).get("evidence", {}).get("screenshot_saved"):
                delete(uid, report["id"])
        _mem.pop(uid, None)
        _bq("DELETE `{ds}.history` WHERE uid = @uid", uid=uid)
        return
    for report in list_reports(uid):
        delete(uid, report["id"])


def move_all(src: str, dst: str) -> int:
    """Hand a guest's history and Shieldy notes to the account they just signed in with. Returns how many checks moved."""
    if src == dst or _db():
        return 0
    moved = list_reports(src)  # newest first
    _ensure_loaded(dst)
    ids = {r["id"] for r in moved}
    # The guest's checks were most likely just made, so they go after (newer than) what the account already had.
    kept = [(k, v) for k, v in _mem[dst].items() if k not in ids]
    _mem[dst] = collections.OrderedDict((kept + [(r["id"], r) for r in reversed(moved)])[-MAX_HISTORY:])
    _mem.pop(src, None)
    notes = get_field(src, "chat_notes", [])
    if notes:
        mine = get_field(dst, "chat_notes", [])
        known = {n["text"].lower() for n in mine}
        set_field(dst, "chat_notes", (mine + [n for n in notes if n["text"].lower() not in known])[-60:])
        set_field(src, "chat_notes", [])
    if _dataset() and moved:
        _bq("UPDATE `{ds}.history` SET uid = @dst WHERE uid = @src", src=src, dst=dst)
    return len(moved)
