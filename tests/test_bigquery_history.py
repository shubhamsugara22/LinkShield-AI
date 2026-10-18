import json
from types import SimpleNamespace as Row

from fastapi.testclient import TestClient

from app.main import app
from app.security import api, identity, storage


class FakeBigQuery:
    """Keeps rows like the real tables do, and records every statement."""
    def __init__(self):
        self.history, self.profiles, self.sql = [], {}, []

    def __call__(self, sql, wait=False, **p):
        self.sql.append(sql.split()[0])
        if sql.startswith("INSERT"):
            self.history.append({"uid": p["uid"], "id": p["id"], "report": p["report"], "source": p["source"], "contact": p["contact"]})
        elif sql.startswith("SELECT report"):
            return [Row(report=r["report"]) for r in self.history if r["uid"] == p["uid"]][::-1]
        elif sql.startswith("DELETE") and "scan_id" in sql:
            self.history = [r for r in self.history if not (r["uid"] == p["uid"] and r["id"] == p["id"])]
        elif sql.startswith("DELETE"):
            self.history = [r for r in self.history if r["uid"] != p["uid"]]
        elif sql.startswith("UPDATE"):
            for r in self.history:
                if r["uid"] == p["src"]:
                    r["uid"] = p["dst"]
        elif sql.lstrip().startswith("MERGE"):
            field = "prefs" if "SET prefs" in sql else "chat_notes"
            self.profiles.setdefault(p["uid"], {"prefs": None, "chat_notes": None})[field] = p["v"]
        elif "FROM `{ds}.profiles`" in sql:
            row = self.profiles.get(p["uid"])
            return [Row(**row)] if row else []
        return []


def restart():
    """What a redeploy does: this server forgets everything it held in memory."""
    storage._mem.clear(); storage._loaded.clear(); storage._profiles.clear()


def setup(monkeypatch):
    monkeypatch.setenv("ENABLE_FIRESTORE", "0"); monkeypatch.setenv("BQ_DATASET", "proj.linkshield")
    fake = FakeBigQuery()
    monkeypatch.setattr(storage, "_bq", fake)
    restart()
    return fake


def report(i):
    return {"id": f"r{i}", "kind": "check", "level": "low", "score": 3, "label": f"example{i}.com", "links": [], "uploads": []}


def test_history_survives_a_restart_and_deletes_reach_bigquery(monkeypatch):
    fake = setup(monkeypatch)
    storage.save("g-1", report(1)); storage.save("g-1", report(2))
    restart()
    assert [r["id"] for r in storage.list_reports("g-1")] == ["r2", "r1"]
    storage.delete("g-1", "r1")
    restart()
    assert [r["id"] for r in storage.list_reports("g-1")] == ["r2"]
    storage.delete_all("g-1")
    restart()
    assert storage.list_reports("g-1") == [] and fake.sql.count("INSERT") == 2


def test_each_check_records_where_it_came_from_and_who_sent_it(monkeypatch):
    fake = setup(monkeypatch)
    storage.save("g-1", report(1))
    storage.save("wa-x", report(2), "whatsapp", "919876543210")
    storage.save("tg-y", report(3), "telegram", "123456789")
    assert [(r["source"], r["contact"]) for r in fake.history] == [("website", ""), ("whatsapp", "919876543210"), ("telegram", "123456789")]


def test_preferences_and_notes_survive_a_restart(monkeypatch):
    setup(monkeypatch)
    storage.set_prefs("g-1", {"language": "hi"}); storage.set_field("g-1", "chat_notes", [{"id": "n", "text": "Bank is SBI", "kind": "fact"}])
    restart()
    assert storage.get_prefs("g-1") == {"language": "hi"}
    assert storage.get_field("g-1", "chat_notes", [])[0]["text"] == "Bank is SBI"


def test_guest_checks_move_into_the_account_on_sign_in(monkeypatch):
    setup(monkeypatch)
    monkeypatch.setenv("AUTH_REQUIRED", "0"); monkeypatch.setenv("GOOGLE_CLIENT_ID", "cid")
    monkeypatch.setattr(identity, "_google", lambda t: {"uid": "g-7", "email": "a@b.c", "name": "A", "picture": None})
    api._hits.clear()
    session = "a38e8dad-d196-4fda-8c43-9be5eecb080f"
    guest = identity.account(None, session)["uid"]
    storage.save(guest, report(5))
    client = TestClient(app)
    r = client.post("/api/v1/me/claim-guest", headers={"Authorization": "Bearer t", "X-Linkshield-Session": session})
    assert r.json() == {"moved": 1}
    restart()
    assert [r["id"] for r in storage.list_reports("g-7")] == ["r5"] and storage.list_reports(guest) == []
    # A guest cannot claim anything.
    assert client.post("/api/v1/me/claim-guest", headers={"X-Linkshield-Session": session}).status_code == 400


def test_queries_go_to_the_real_client_with_parameters(monkeypatch):
    """The real path, with only the network call replaced: parameters are typed and the dataset is filled in."""
    monkeypatch.setenv("ENABLE_FIRESTORE", "0"); monkeypatch.setenv("BQ_DATASET", "proj.linkshield")
    seen = {}

    class Client:
        def query(self, sql, job_config, location):
            seen.update(sql=sql, location=location, params={p.name: (p.type_, p.value) for p in job_config.query_parameters})
            return Row(result=lambda timeout: [])
    monkeypatch.setattr(storage, "_bq_conn", Client())
    storage._bq("DELETE `{ds}.history` WHERE uid = @uid AND score = @n", uid="g-1", n=3)
    assert seen["sql"] == "DELETE `proj.linkshield.history` WHERE uid = @uid AND score = @n"
    assert seen["params"] == {"uid": ("STRING", "g-1"), "n": ("INT64", 3)} and seen["location"] == "asia-south1"
    assert storage._bq("SELECT 1", wait=True) == []
