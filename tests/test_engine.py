import json
import asyncio
import httpx
import pytest
from fastapi.testclient import TestClient

from app import bots
from app.main import app
from app.security import api, engine, orchestrator, providers
from app.security.signals import detect_tactics, inspect_message, inspect_url
from sandbox.filescan import analyze

SESSION = 'c38e8dad-d196-4fda-8c43-9be5eecb080f'
H = {'X-Linkshield-Session': SESSION}
client = TestClient(app)
PDF = {'name':'bill.pdf','type':'PDF document','kind':'document','size':900,'sha256':'b'*64,'complete':True,'verdict':'clean','score':0,
       'findings':[],'checks':[],'notes':[]}


def _impersonation(url):
    return any(s['code'] == 'impersonation' for s in inspect_url(url))

def test_real_brand_addresses_are_not_called_fakes():
    for real in ('https://sbi.bank.in/', 'https://www.hdfc.bank.in/login', 'https://netbanking.hdfcbank.com/', 'https://www.icicidirect.com/',
                 'https://www.amazon.co.uk/dp/1', 'https://s3.amazonaws.com/bucket/x', 'https://www.sbicard.com/', 'https://epfo.gov.in/',
                 'https://paytmmoney.com/', 'https://wa.me/919999999999'):
        assert not _impersonation(real), real
    for fake in ('https://sbi-kyc-update.example.com/', 'https://hdfcbank-alert.top/', 'https://amazon-prize.click/win', 'https://paytm.kyc-verify.in/'):
        assert _impersonation(fake), fake

def test_indian_language_scam_wording_is_recognised():
    hindi = 'आपका खाता ब्लॉक हो जाएगा। तुरंत केवाईसी अपडेट करें और ओटीपी बताएं।'
    assert any(s['code'] == 'social_pressure' for s in inspect_url('https://example.com/', hindi))
    codes = {s['code'] for s in inspect_message(hindi)}
    assert {'secret_request', 'social_pressure'} <= codes
    assert {'urgency', 'fear'} <= set(detect_tactics(hindi))
    assert {s['code'] for s in inspect_message('Please share the OTP sent to your phone and install AnyDesk')} >= {'secret_request', 'remote_app'}
    assert inspect_message('See you at dinner on Friday, the food was fine last time') == []

def test_links_written_inside_documents_are_listed():
    pdf = b'%PDF-1.4\n1 0 obj<</Type/Annot/A<</S/URI/URI(https://pay.example.com/bill?id=7)>>>>endobj\n2 0 obj<</URI <68747470733a2f2f6865782e6578616d706c652e6f72672f>>>endobj\n%%EOF'
    assert analyze(pdf, 'bill.pdf')['links'] == ['https://pay.example.com/bill?id=7', 'https://hex.example.org/']
    html = b'<html><body><a href="https://login.example.net/a?x=1&amp;y=2">Sign in</a></body></html>'
    assert analyze(html, 'invoice.html')['links'] == ['https://login.example.net/a?x=1&y=2']

@pytest.mark.asyncio
async def test_virustotal_lookup_sends_only_the_fingerprint(monkeypatch):
    seen = []
    def handler(request):
        seen.append(request)
        if request.url.path.endswith('a'*64):
            return httpx.Response(404, json={'error': {'code': 'NotFoundError'}})
        return httpx.Response(200, json={'data': {'attributes': {'last_analysis_stats': {'malicious': 41, 'suspicious': 2, 'harmless': 0, 'undetected': 25},
                                                                 'popular_threat_classification': {'suggested_threat_label': 'trojan.agent'}}}})
    assert not (await providers.virustotal('b'*64))['checked']
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'key')
    transport = httpx.MockTransport(handler)
    assert (await providers.virustotal('a'*64, transport)) == {'checked': True, 'known': False, 'malicious': 0, 'suspicious': 0, 'engines': 0, 'error': None}
    hit = await providers.virustotal('b'*64, transport)
    assert hit['malicious'] == 41 and hit['engines'] == 68 and hit['threat_label'] == 'trojan.agent'
    assert all(r.method == 'GET' and r.content == b'' and r.headers['x-apikey'] == 'key' for r in seen)
    assert not (await providers.virustotal(None, transport))['checked']

def _quiet(monkeypatch, vt=None):
    async def no_threat(_): return {'checked': False, 'threats': [], 'error': 'Not configured'}
    async def no_ai(*args, **kw): return None
    async def lookup(sha, transport=None): return vt or {'checked': False, 'error': 'off'}
    monkeypatch.setattr(orchestrator, 'google_web_risk', no_threat)
    monkeypatch.setattr(orchestrator, 'gemini_explain', no_ai)
    monkeypatch.setattr(orchestrator, 'virustotal', lookup)
    monkeypatch.setattr(engine, 'gemini_summary', no_ai)
    monkeypatch.setenv('DISABLE_GOOGLE', '1')

@pytest.mark.asyncio
async def test_known_malware_and_dangerous_links_inside_a_file_block_the_green_flag(monkeypatch):
    _quiet(monkeypatch, {'checked': True, 'known': True, 'malicious': 30, 'suspicious': 0, 'engines': 70})
    async def upload(data, name, content_type=''): return {'status': 'completed', 'file': {**PDF, 'name': name}}
    monkeypatch.setattr(orchestrator, 'inspect_upload', upload)
    out = await orchestrator.scan_upload(b'%PDF', 'bill.pdf')
    assert out['level'] == 'critical' and out['threats'] == ['KNOWN_MALWARE'] and out['files'][0]['verdict'] == 'dangerous'
    assert out['narrative']['recommendations'][0] == 'Do not download or open this file.'

    _quiet(monkeypatch, {'checked': True, 'known': False, 'malicious': 0, 'suspicious': 0, 'engines': 0})
    visited = []
    async def with_links(data, name, content_type=''):
        return {'status': 'completed', 'file': {**PDF, 'name': name, 'links': ['https://sbi-kyc-update.example.com/pay', 'https://www.w3.org/ns', 'not a link']}}
    async def worker(url):
        visited.append(url)
        return {'status': 'completed', 'target': 'page', 'files': [{**PDF, 'links': ['https://deeper.example.org/']}],
                'evidence': {'final_url': url, 'password_inputs': 1, 'payment_inputs': 1, 'redirects': 0, 'downloads': 0, 'cross_domain_forms': 0, 'blocked_requests': 0}}
    monkeypatch.setattr(orchestrator, 'inspect_upload', with_links)
    monkeypatch.setattr(orchestrator, 'investigate', worker)
    out = await orchestrator.scan_upload(b'%PDF', 'bill.pdf')
    item = out['files'][0]
    # Only the tappable link is followed, and links inside the file it leads to are not followed again.
    assert visited == ['https://sbi-kyc-update.example.com/pay']
    assert item['links_found'] == 3 and 'links' not in item and item['embedded_links'][0]['level'] == 'high'
    assert out['level'] == 'high' and any(s['code'] == 'dangerous_link_inside' for s in out['signals'])
    assert any('known-malware database' in c['label'] for c in item['checks'])

@pytest.mark.asyncio
async def test_check_joins_claims_links_and_files_under_one_summary(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.setattr(engine, 'gemini_on', lambda: True)
    async def extract(text, image, audio):
        assert image and image[1] == 'image/png' and audio is None
        return {'transcript': 'RBI will cancel all 500 rupee notes tomorrow. Details: sbi-kyc-update.example.com/verify', 'input_language': 'en',
                'claims': ['RBI will cancel all 500 rupee notes tomorrow.'], 'tactics': ['fear']}
    async def claim(text, lang):
        return {'claim_id': 'abc', 'claim': text, 'verdict': 'false', 'confidence': 0.9, 'verdict_label': 'False', 'explanation': 'RBI denied this.',
                'sources': [{'title': 'PIB Fact Check', 'url': 'https://pib.gov.in/x'}], 'grounded': True, 'cached': False}
    async def worker(url): return {'status': 'completed', 'target': 'page', 'files': [], 'evidence': {'final_url': url, 'password_inputs': 1}}
    async def upload(data, name, content_type=''): return {'status': 'completed', 'file': {**PDF, 'name': name, 'type': 'PNG image', 'kind': 'image'}}
    monkeypatch.setattr(engine, 'gemini_extract', extract)
    monkeypatch.setattr(engine, 'gemini_claim', claim)
    monkeypatch.setattr(orchestrator, 'investigate', worker)
    monkeypatch.setattr(orchestrator, 'inspect_upload', upload)
    out = await engine.check('', 'hi', (b'\x89PNG\r\n\x1a\n' + b'0'*40, 'forward.png', 'image/png'))
    assert out['kind'] == 'check' and out['language'] == 'hi'
    assert [s['id'] for s in out['steps']] == ['extract', 'links', 'files', 'claims', 'summary']
    assert out['links'][0]['level'] == 'high' and out['uploads'][0]['level'] == 'low' and out['claims'][0]['verdict'] == 'false'
    assert out['level'] == 'high' and out['summary']['headline'] == 'Do not open this link' and out['summary']['generated_by'] == 'rules'
    assert any('Do not forward' in s for s in out['summary']['next_steps']) and 'urgency' not in out['tactics'] and 'fear' in out['tactics']
    assert out['input']['attachment']['read_as'] == 'image' and out['transcript'].startswith('RBI will cancel')

    # The summary writer may explain the verdict but the level it is given is never taken from its answer.
    async def summary(level, evidence, language):
        assert level == 'high' and evidence['claims'][0]['verdict'] == 'false' and 'sbi-kyc-update[.]example[.]com' == evidence['links'][0]['website']
        return {'headline': 'यह लिंक न खोलें', 'explanation': 'x', 'next_steps': ['y'], 'generated_by': 'gemini_vertex_ai', 'level': 'low'}
    monkeypatch.setattr(engine, 'gemini_summary', summary)
    out = await engine.check('', 'hi', (b'\x89PNG\r\n\x1a\n' + b'0'*40, 'forward.png', 'image/png'))
    assert out['level'] == 'high' and out['summary']['headline'] == 'यह लिंक न खोलें' and out['steps'][-1]['status'] == 'completed'

@pytest.mark.asyncio
async def test_check_without_gemini_is_honest_about_what_it_skipped(monkeypatch):
    _quiet(monkeypatch)
    monkeypatch.delenv('SANDBOX_URL', raising=False)
    out = await engine.check('Dear customer, share the OTP you received with our agent to stop your account being blocked today')
    assert out['level'] == 'caution' and out['summary']['headline'] == 'This message shows scam warning signs'
    assert out['claims'] == [] and any('not fact-checked' in n for n in out['notes']) and out['summary']['next_steps'][0].startswith('Never share an OTP')
    out = await engine.check('', '', (b'OggS' + b'0'*20, 'voice-note.webm', 'audio/webm'), recording=True)
    assert out['level'] == 'unverified' and out['uploads'] == [] and out['summary']['headline'] == 'Nothing here could be checked'
    assert out['steps'][0]['status'] == 'unavailable'
    out = await engine.check('hello there')
    assert out['level'] == 'unverified' and out['links'] == []
    with pytest.raises(ValueError):
        await engine.check('   ')

def test_checks_endpoint_history_prefs_and_guarded_legacy_routes(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', '0')
    monkeypatch.setenv('DISABLE_GOOGLE', '1')
    monkeypatch.delenv('SANDBOX_URL', raising=False)
    monkeypatch.delenv('SANDBOX_TOKEN', raising=False)
    api._hits.clear()
    r = client.post('/api/v1/checks', headers=H, data={'text': 'Your SBI account is blocked, update KYC: https://sbi-kyc-update.example.com/verify'},
                    files={'file': ('holiday.jpg', b'\xff\xd8\xff\xe0data', 'image/jpeg')})
    assert r.status_code == 200, r.text
    obj = r.json()
    assert obj['kind'] == 'check' and obj['links'][0]['domain'] == 'sbi-kyc-update.example.com' and obj['uploads'][0]['target'] == 'upload'
    assert obj['level'] == 'caution' and obj['history_saved']
    assert client.get(f"/api/v1/scans/{obj['id']}", headers=H).json()['label'] == 'sbi-kyc-update.example.com'
    assert client.delete(f"/api/v1/scans/{obj['id']}", headers=H).status_code == 204
    assert client.post('/api/v1/checks', headers=H, data={'text': ''}).status_code == 422
    assert client.post('/api/v1/checks', headers=H, data={'text': 'hi', 'language': 'xx'}).status_code == 422
    assert client.post('/api/v1/checks', data={'text': 'hi'}).status_code == 400
    monkeypatch.setattr(api, 'MAX_UPLOAD_BYTES', 8)
    assert client.post('/api/v1/checks', headers=H, files={'file': ('a.bin', b'1'*90000, 'application/octet-stream')}).status_code == 413

    assert client.get('/api/v1/me', headers=H).json()['language'] == ''
    assert client.put('/api/v1/me', headers=H, json={'language': 'ta'}).status_code == 200
    assert client.get('/api/v1/me', headers=H).json()['language'] == 'ta'
    assert client.put('/api/v1/me', headers=H, json={'language': 'zz'}).status_code == 422

    # The old endpoints used to be open to anyone.
    assert client.post('/api/check', data={'text': 'x'}).status_code == 400
    assert client.post('/api/tts', json={'text': 'x'}).status_code == 400
    assert client.get('/api/trends').status_code == 400
    assert client.post('/api/v1/tts', headers=H, json={'text': 'hello'}).status_code == 503
    assert client.get('/api/v1/trends', headers=H).json()['source'] == 'memory'

def test_rate_limit_applies_to_checks(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', '0')
    monkeypatch.setenv('DISABLE_GOOGLE', '1')
    monkeypatch.delenv('SANDBOX_URL', raising=False)
    api._hits.clear()
    n = api.LIMITS['check']
    codes = [client.post('/api/v1/checks', headers=H, data={'text': 'hello'}).status_code for _ in range(n + 1)]
    assert codes[:n] == [200]*n and codes[n] == 429
    api._hits.clear()

def test_share_target_and_app_shell():
    assert client.get('/manifest.webmanifest').json()['share_target']['action'] == '/share'
    assert 'fetch' in client.get('/sw.js').text
    r = client.post('/share', data={'title': 'Fwd', 'text': 'look at this', 'url': 'https://example.com/a'}, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'].startswith('/app?text=Fwd+look+at+this+https%3A%2F%2Fexample.com%2Fa')
    assert client.get('/legacy', follow_redirects=False).status_code == 308

def test_telegram_bot_checks_what_is_forwarded(monkeypatch):
    monkeypatch.setenv('DISABLE_GOOGLE', '1')
    monkeypatch.delenv('SANDBOX_URL', raising=False)
    api._hits.clear()
    monkeypatch.setenv('ENABLE_FIRESTORE', '0'); monkeypatch.delenv('BQ_DATASET', raising=False)
    update = {'message': {'message_id': 5, 'chat': {'id': 77}, 'caption': 'Urgent: share the OTP to keep your account. bit.ly/x1',
                          'document': {'file_id': 'F1', 'file_name': 'invoice.pdf', 'mime_type': 'application/pdf', 'file_size': 2000}}}
    assert client.post('/api/v1/bots/telegram', json=update).status_code == 404
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', '123:abc')
    monkeypatch.setenv('TELEGRAM_WEBHOOK_SECRET', 'hook-secret')
    assert client.post('/api/v1/bots/telegram', json=update).status_code == 401
    assert client.post('/api/v1/bots/telegram', json=update, headers={'X-Telegram-Bot-Api-Secret-Token': 'wrong'}).status_code == 401
    calls = []
    def telegram(request):
        calls.append((request.url.path, request.content))
        if request.url.path.endswith('/getFile'):
            return httpx.Response(200, json={'ok': True, 'result': {'file_path': 'documents/file_1.pdf'}})
        if request.url.path.startswith('/file/'):
            return httpx.Response(200, content=b'%PDF-1.4 demo')
        return httpx.Response(200, json={'ok': True, 'result': {}})
    monkeypatch.setattr(bots, 'TRANSPORT', httpx.MockTransport(telegram))
    ok = client.post('/api/v1/bots/telegram', json=update, headers={'X-Telegram-Bot-Api-Secret-Token': 'hook-secret'})
    assert ok.status_code == 200
    paths = [p for p, _ in calls]
    assert paths == ['/bot123:abc/sendChatAction', '/bot123:abc/getFile', '/file/bot123:abc/documents/file_1.pdf', '/bot123:abc/sendMessage']
    sent = json.loads(calls[-1][1])
    # A short verdict that answers the forwarded message, with a button to the full report; no tappable suspicious link.
    assert sent['text'].splitlines()[0] in bots.VERDICT.values() and 'Full report: http://testserver/app#r=' in sent['text']
    assert sent['reply_to_message_id'] == 5 and 'https://bit.ly' not in sent['text']
    token = sent['text'].split('#r=')[1].split()[0]
    # The link opens the saved report, which lists the link and the file in full ...
    report = client.get(f'/api/v1/shared/{token}', headers=H).json()
    assert report['links'][0]['domain'] == 'bit.ly' and report['uploads'][0]['domain'] == 'invoice.pdf'
    # ... and keeps it in the viewer's own history, once.
    assert client.post(f'/api/v1/shared/{token}/save', headers=H).json() == {'saved': True}
    assert client.post(f'/api/v1/shared/{token}/save', headers=H).json() == {'saved': False}
    assert report['id'] in [r['id'] for r in client.get('/api/v1/scans', headers=H).json()['items']]
    # A link that was altered opens nothing.
    assert client.get(f'/api/v1/shared/{token[:-3]}abc', headers=H).status_code == 404

def test_whatsapp_webhook_requires_metas_signature(monkeypatch):
    import hashlib, hmac, json
    monkeypatch.setenv('DISABLE_GOOGLE', '1')
    monkeypatch.delenv('SANDBOX_URL', raising=False)
    api._hits.clear()
    monkeypatch.setenv('WHATSAPP_TOKEN', 'tok')
    monkeypatch.setenv('WHATSAPP_APP_SECRET', 'app-secret')
    monkeypatch.setenv('WHATSAPP_VERIFY_TOKEN', 'verify-me')
    assert client.get('/api/v1/bots/whatsapp?hub.mode=subscribe&hub.verify_token=verify-me&hub.challenge=42').text == '42'
    assert client.get('/api/v1/bots/whatsapp?hub.mode=subscribe&hub.verify_token=nope&hub.challenge=42').status_code == 403
    body = json.dumps({'entry': [{'changes': [{'value': {'metadata': {'phone_number_id': 'P1'},
            'messages': [{'id': 'wamid.1', 'from': '919999999999', 'type': 'text', 'text': {'body': 'You won a lottery! Pay the processing fee at prize-claim.top/win'}}]}}]}]}).encode()
    assert client.post('/api/v1/bots/whatsapp', content=body, headers={'X-Hub-Signature-256': 'sha256=bad'}).status_code == 401
    sent = []
    def graph(request):
        sent.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={})
    monkeypatch.setattr(bots, 'TRANSPORT', httpx.MockTransport(graph))
    sig = 'sha256=' + hmac.new(b'app-secret', body, hashlib.sha256).hexdigest()
    assert client.post('/api/v1/bots/whatsapp', content=body, headers={'X-Hub-Signature-256': sig}).status_code == 200
    assert sent[0][0] == '/v21.0/P1/messages' and sent[0][1]['to'] == '919999999999' and sent[0][1]['context'] == {'message_id': 'wamid.1'}
    body = sent[0][1]['text']['body']
    assert body.splitlines()[0] in bots.VERDICT.values() and '/app#r=' in body and 'https://prize-claim' not in body



def test_claim_only_level_has_matching_score(monkeypatch):
    async def extract(text, image, audio):
        return {"transcript": text, "input_language": "en", "claims": ["Lemon water cures diabetes"], "tactics": ["miracle_cure"]}
    async def claim(text, language):
        return {"claim_id": "a", "claim": text, "verdict": "false", "confidence": 0.9, "verdict_label": "False", "explanation": "x", "sources": [], "grounded": True, "cached": False}
    async def no_summary(*args):
        return None
    monkeypatch.setattr(engine, "gemini_on", lambda: True)
    monkeypatch.setattr(engine, "gemini_extract", extract)
    monkeypatch.setattr(engine, "gemini_claim", claim)
    monkeypatch.setattr(engine, "gemini_summary", no_summary)
    report = asyncio.run(engine.check(text="Lemon water cures diabetes"))
    assert report["level"] == "caution"
    assert report["score"] >= engine.SCORE_FLOOR["caution"]


def test_gemini_patterns_must_quote_the_message_and_are_capped():
    text = "Your electricity will be cut tonight. Call officer 98xxxx and share OTP now."
    patterns = [{"name": "Electricity disconnection scam", "quote": "electricity will be cut tonight", "severity": "high"},
                {"name": "OTP sharing", "quote": "share OTP now", "severity": "high"},
                {"name": "Invented", "quote": "words that are not in the message", "severity": "high"}]
    signals = engine.pattern_signals(patterns, text)
    assert [s["label"] for s in signals] == ["Matches a known scam: Electricity disconnection scam", "Matches a known scam: OTP sharing"]
    assert sum(s["weight"] for s in signals) == engine.PATTERN_CAP
    assert engine.pattern_signals([], "Save time. Download Inshorts to read news in 60 words.") == []


def test_chat_export_checks_newest_links(monkeypatch):
    seen = []
    async def fake_scan(payload, depth=0, explain=True):
        seen.append(payload.url)
        return {"id": "x", "url": payload.url, "domain": payload.url.split("/")[2], "level": "low", "score": 0, "status": "completed",
                "target": "page", "files": [], "signals": [], "threats": [], "sandbox": {"status": "completed", "evidence": {}}, "web_risk": {"checked": False},
                "narrative": {"headline": "No warning signs", "explanation": "Nothing found.", "recommendations": []}}
    monkeypatch.setattr(engine, "scan", fake_scan)
    monkeypatch.setattr(engine, "gemini_on", lambda: False)
    lines = [f"12/03/24, 9:{i:02d} pm - Asha: see https://site{i}.example.com/page" for i in range(8)]
    chat = ("\n".join(lines)).encode()
    report = asyncio.run(engine.check(attachment=(chat, "WhatsApp Chat with Asha.txt", "text/plain")))
    assert seen == [f"https://site{i}.example.com/page" for i in (7, 6, 5, 4, 3)]
    assert report["uploads"] == [] and any("Chat export" in n for n in report["notes"])
    assert engine.chat_export(b"just a note\nwith https://example.com", "note.txt") is None


def test_telegram_errors_never_log_the_bot_token(monkeypatch, caplog):
    import asyncio
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', '123:SECRET-TOKEN')
    monkeypatch.setattr(bots, 'TRANSPORT', httpx.MockTransport(lambda r: httpx.Response(400, json={'ok': False, 'description': 'Bad Request: chat not found'})))
    asyncio.run(bots.handle_telegram({'message': {'chat': {'id': 1}, 'text': 'hi there'}}))
    assert 'chat not found' in caplog.text and 'SECRET-TOKEN' not in caplog.text
