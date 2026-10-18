import { buddySvg, CRITTERS, owlSvg, botSvg } from './characters.js';
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const store = {
  get(key) { try { return localStorage.getItem(key); } catch { return null; } },
  set(key, value) { try { localStorage.setItem(key, value); } catch { /* private mode */ } },
};
const sessionId = (() => {
  let id = store.get('linkshield_demo_session');
  if (!id || !/^[a-f0-9-]{36}$/.test(id)) {
    id = crypto.randomUUID(); store.set('linkshield_demo_session', id);
  }
  return id;
})();
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// Sign in with Google: the login page keeps the Google ID token here; it lasts about an hour.
const TOKEN_KEY = 'ls_tok';
const jwt = t => { try { return JSON.parse(atob(t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch { return null; } };
function signedIn() {
  const t = store.get(TOKEN_KEY); const p = t && jwt(t);
  return p && p.exp * 1000 > Date.now() + 30000 ? { token: t, ...p } : null;
}
function toLogin(reason = '') {
  try { localStorage.removeItem(TOKEN_KEY); } catch { /* private mode */ }
  location.replace(`/?${reason}=1&next=${encodeURIComponent(location.hash || '#scan')}`);
}
let caps = null;
let reports = [];
let scanning = false;
let historyFilter = 'all';
let attachments = []; // [{file, recording}] waiting in the check box
const MAX_BATCH = 10; // things checked in one go, each on its own
let batch = []; // the current batch: [{item, result, error}]
let recorder = null;
let speech = null; // whatever is currently reading a verdict aloud
let installPrompt = null;
// Reports carry no timestamp, so remember locally when each scan was made on this device.
const scanTimes = (() => { try { return JSON.parse(store.get('linkshield_scan_times') || '{}'); } catch { return {}; } })();

const LEVELS = {
  critical: { label: 'Known threat', icon: 'shield-x', meaning: 'A threat list or antivirus engines already know something in what you sent.' },
  high: { label: 'High risk', icon: 'alert', meaning: 'Strong warning signs were found. Treat it as dangerous.' },
  caution: { label: 'Caution advised', icon: 'alert', meaning: 'Some warning signs were found. Verify with the sender before you do anything.' },
  low: { label: 'Low observed risk', icon: 'shield-check', meaning: 'The checks that ran found nothing suspicious. That is not a guarantee of safety.' },
  unverified: { label: 'Unverified', icon: 'help', meaning: 'Too little could be checked to judge this either way.' },
};
const CLAIMS = { false: ['False', 'critical'], misleading: ['Misleading', 'caution'], true: ['True', 'low'], unverifiable: ['Unverifiable', 'unverified'] };
const TACTICS = {
  fear: ['Fear', 'Threatens a loss or punishment so you act before thinking.'], urgency: ['Urgency', 'Sets a deadline so you have no time to check.'],
  fake_authority: ['Borrowed authority', 'Uses the name of a bank, government office or expert to sound official.'],
  forward_chain: ['Forward-this pressure', 'Asks you to pass it on, which is how false messages spread.'],
  miracle_cure: ['Miracle cure', 'Promises a health result that real medicine does not offer.'],
  emotional_bait: ['Too good to be true', 'Dangles a prize, gift or windfall to lower your guard.'], us_vs_them: ['Us against them', 'Sets one group against another to provoke anger.'],
};
const SPEECH_LOCALES = { hi: 'hi-IN', en: 'en-IN', bn: 'bn-IN', ta: 'ta-IN', te: 'te-IN', mr: 'mr-IN', gu: 'gu-IN', kn: 'kn-IN', ml: 'ml-IN', pa: 'pa-IN', ur: 'ur-IN' };
const FILE_VERDICTS = { clean: ['No danger signs', 'low'], suspicious: ['Warning signs', 'caution'], dangerous: ['Dangerous', 'high'], unknown: ['Not fully checked', 'unverified'] };
const KIND_ICONS = { image: 'image', video: 'video', audio: 'music', document: 'doc', archive: 'archive', program: 'cog', web: 'globe', text: 'doc' };
const STATUS = {
  partial: ['Partly checked', 'info'],
  completed: ['Done', 'ok'], rules_fallback: ['Built-in rules', 'info'], unavailable: ['Not available', 'off'],
  not_configured: ['Not set up', 'off'], skipped: ['Skipped', 'off'], blocked: ['Blocked', 'warn'], error: ['Failed', 'warn'],
};
const SOURCES = { local_rules: 'Link pattern', sandbox: 'Safe browser', file_scan: 'File check', file_reputation: 'Antivirus lookup', embedded_link: 'Link inside the file', message_rules: 'Message wording', gemini_patterns: 'Gemini scam knowledge' };
const STAGES = [
  { id: 'read', title: 'Read' }, { id: 'sandbox', title: 'Sandbox' }, { id: 'claims', title: 'Look up' }, { id: 'explain', title: 'Answer' },
];
// What the mascot says for each result. "Low" never claims the thing is safe.
const MOODS = {
  critical: ['alarm', 'Known threat. Stay away!'], high: ['alarm', "Don't open that!"], caution: ['worried', 'Hmm. Be careful.'],
  low: ['happy', 'Nothing bad found.'], unverified: ['worried', "I couldn't see enough."],
};
// Shown while a check runs: [real address, fake address, why].
const QUIZ = [
  ['sbi.co.in', 'sbi.co.in.kyc-verify.top', 'Only the end of the address counts.'],
  ['amazon.in', 'amaz0n-offers.in', 'A zero is standing in for the letter o.'],
  ['paytm.com', 'paytm.com.refund-help.xyz', 'It really ends in refund-help.xyz.'],
  ['incometax.gov.in', 'incometax-gov.in', 'A dash is not a dot.'],
  ['google.com', 'google.com-login.net', 'It really ends in com-login.net.'],
  ['hdfcbank.com', 'hdfcbank.secure-login.co', 'It really ends in secure-login.co.'],
  ['irctc.co.in', 'irctc-refund.co.in', 'Extra words were glued onto the name.'],
];
const EXAMPLES = {
  normal: 'https://example.com',
  pdf: 'https://mozilla.github.io/pdf.js/web/compressed.tracemonkey-pldi-09.pdf',
  fake: 'Dear customer, your SBI account is blocked. Update KYC urgently using this link to avoid suspension. https://sbi-kyc-update.example.com/verify',
  otp: 'Dear customer, your electricity connection will be disconnected tonight at 9:30 pm because your bill was not updated. Call our officer immediately and share the OTP you receive to keep it active.',
  rumour: "Forwarded many times: Drinking hot lemon water every morning cures diabetes completely. Doctors don't want you to know this. Share with everyone in your family!",
};
const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'is.gd', 'rb.gy', 'tiny.cc'];

const esc = s => String(s ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
const defang = s => String(s || '').replace(/^https?:\/\//i, '').replace(/\./g, '[.]').slice(0, 180);
const icon = name => `<svg class="ic"><use href="#i-${name}"/></svg>`;
const levelOf = r => (LEVELS[r?.level] ? r.level : 'unverified');
const isUpload = r => r?.target === 'upload';
const subject = r => (isUpload(r) ? (r.files?.[0]?.name || r.domain || 'Uploaded file') : defang(r.url));
const partsOf = c => [...(c.links || []), ...(c.uploads || [])];
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
// Reports made before the single check box (one link or one file) are shown through the same layout.
function asCheck(r) {
  if (r.kind === 'check') return r;
  const n = r.narrative || {};
  return { id: r.id, kind: 'check', single: true, label: isUpload(r) ? subject(r) : r.domain, level: r.level, score: r.score, language: r.language,
    claims: [], tactics: [], message_signals: [], notes: [], transcript: '', links: isUpload(r) ? [] : [r], uploads: isUpload(r) ? [r] : [],
    summary: { headline: n.headline, explanation: n.explanation, next_steps: n.recommendations || [], generated_by: n.generated_by },
    steps: [], elapsed_ms: r.elapsed_ms, disclaimer: r.disclaimer };
}
function titleOf(c) {
  if (c.links?.length) return defang(c.links[0].url);
  if (c.uploads?.length) return subject(c.uploads[0]);
  return String(c.label || 'Message').slice(0, 90);
}
function countsOf(c) {
  const files = (c.uploads || []).length + (c.links || []).filter(r => r.files?.length).length;
  const bits = [c.links?.length && plural(c.links.length, 'link'), files && plural(files, 'file'), c.claims?.length && plural(c.claims.length, 'claim')].filter(Boolean);
  return bits.join(' · ') || 'Message wording only';
}
function fmtSize(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} bytes`;
  if (n < 1048576) return `${(n / 1024).toFixed(n < 10240 ? 1 : 0)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

function timeAgo(ts) {
  if (!ts) return '';
  const mins = Math.round((Date.now() - ts) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins} min ago`;
  if (mins < 1440) return `${Math.round(mins / 60)} h ago`;
  return new Date(ts).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}

function toast(message) {
  const t = $('#toast');
  t.textContent = message; t.classList.add('show');
  clearTimeout(t._timer); t._timer = setTimeout(() => t.classList.remove('show'), 4000);
}

function countUp(el, to) {
  const from = Number(el.textContent) || 0;
  if (reducedMotion || from === to) { el.textContent = to; return; }
  const start = performance.now();
  const tick = now => {
    const k = Math.min(1, (now - start) / 700);
    el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function ask(title, text, okLabel = 'Delete') {
  return new Promise(resolve => {
    const dialog = $('#confirmDialog');
    $('#confirmTitle').textContent = title; $('#confirmText').textContent = text; $('#confirmOk').textContent = okLabel;
    dialog.returnValue = '';
    dialog.onclose = () => resolve(dialog.returnValue === 'ok');
    dialog.showModal();
  });
}

/* ───────── API ───────── */
async function headers(json = true) {
  const h = { 'X-Linkshield-Session': sessionId };
  if (json) h['Content-Type'] = 'application/json';
  const me = signedIn();
  if (me) h.Authorization = `Bearer ${me.token}`;
  else if (store.get(TOKEN_KEY)) toLogin('expired'); // the hour is up: Google signs them straight back in
  return h;
}
async function api(path, options = {}) {
  const res = await fetch('/api/v1' + path, { ...options, headers: { ...(await headers(!(options.body instanceof FormData))), ...(options.headers || {}) } });
  if (res.status === 401 && store.get(TOKEN_KEY)) toLogin('expired');
  if (!res.ok) {
    let detail = 'Request failed';
    try { const obj = await res.json(); detail = typeof obj.detail === 'string' ? obj.detail : detail; } catch { /* keep default */ }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

/* ───────── Navigation ───────── */
const VIEWS = { scan: 'Check', history: 'History' };
function route(view) {
  if (!VIEWS[view]) view = 'scan';
  $$('.view').forEach(v => v.classList.toggle('hidden', v.id !== `view-${view}`));
  $$('.nav-item').forEach(x => x.classList.toggle('active', x.dataset.view === view));
  document.title = `${VIEWS[view]} · LinkShield AI`;
  if (view === 'history') loadHistory();
  window.scrollTo({ top: 0, behavior: reducedMotion ? 'auto' : 'smooth' });
}
function go(view) {
  // pushState does not fire hashchange, so the view is routed exactly once.
  if (location.hash.slice(1) !== view) history.pushState(null, '', '#' + view);
  const changing = $(`#view-${view}`)?.classList.contains('hidden');
  // Switching tabs cross-fades where the browser supports view transitions.
  if (changing && document.startViewTransition && !reducedMotion && document.visibilityState === 'visible') {
    const vt = document.startViewTransition(() => route(view));
    // An interrupted transition (a second tap, or leaving the page) is harmless; the view is still switched.
    [vt.ready, vt.finished, vt.updateCallbackDone].forEach(p => p.catch(() => {}));
  } else route(view);
}

/* ───────── URL helpers ───────── */
function parseUrl(raw) {
  let s = (raw || '').trim();
  if (!s || /\s/.test(s)) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  try { const u = new URL(s); return u.hostname.includes('.') ? u : null; } catch { return null; }
}
function splitHost(host) {
  if (/^[\d.]+$/.test(host) || host.includes(':')) return { sub: '', main: host, ip: true };
  const parts = host.split('.');
  const twoLevel = parts.length > 2 && parts.at(-1).length === 2 && ['co', 'com', 'gov', 'org', 'net', 'ac', 'edu'].includes(parts.at(-2));
  const n = twoLevel ? 3 : 2;
  return { sub: parts.slice(0, -n).join('.'), main: parts.slice(-n).join('.'), ip: false };
}
// A quick, on-device look at the address so people learn which part matters. Not a verdict.
function renderAnatomy(box, raw) {
  const u = parseUrl(raw);
  if (!u) { box.hidden = true; box.innerHTML = ''; return; }
  const { sub, main, ip } = splitHost(u.hostname);
  const rest = (u.pathname === '/' ? '' : u.pathname) + u.search;
  let note = `The part that matters is <b>${esc(main)}</b>.`;
  let tone = '';
  if (u.protocol === 'http:') { note = 'This link is not encrypted (http). Be extra careful with it.'; tone = 'warn'; }
  if (sub && sub !== 'www') { note = `The real website is <b>${esc(main)}</b>. Anything written before it can be made up.`; tone = 'warn'; }
  if (SHORTENERS.includes(u.hostname)) { note = 'This is a short link. It hides where you will really end up.'; tone = 'warn'; }
  if (u.hostname.includes('xn--')) { note = 'This address uses special characters that can imitate another site.'; tone = 'warn'; }
  if (ip) { note = 'This link goes to a raw number instead of a named website. That is unusual.'; tone = 'warn'; }
  box.innerHTML = `<div class="anatomy-url"><span class="part scheme ${u.protocol === 'http:' ? 'bad' : ''}">${icon('lock')}${esc(u.protocol.replace(':', ''))}</span>${sub ? `<span class="part sub">${esc(sub)}.</span>` : ''}<span class="part main">${esc(main)}</span>${rest ? `<span class="part rest">${esc(rest.slice(0, 60))}${rest.length > 60 ? '…' : ''}</span>` : ''}</div><p class="anatomy-note ${tone}">${icon(tone ? 'alert' : 'info')}<span>${note}</span></p>`;
  box.hidden = false;
}
// The address breakdown only makes sense when the box holds one link and nothing else.
function smartInput(input, box) {
  input.addEventListener('input', () => renderAnatomy(box, /\s/.test(input.value.trim()) ? '' : input.value));
}

/* ───────── History ───────── */
function updateStats() {
  countUp($('#statTotal'), reports.length);
  countUp($('#statRisk'), reports.filter(r => ['critical', 'high'].includes(r.level)).length);
}
function historyRow(r, i) {
  const c = asCheck(r);
  const lv = levelOf(c);
  const score = Math.min(100, Number(c.score) || 0);
  const when = timeAgo(scanTimes[c.id]);
  return `<article class="hrow lvl-${lv}" style="--i:${i}">
    <div class="mini" style="--p:${score}"><b>${score}</b></div>
    <div class="hmain"><strong>${esc(titleOf(c))}</strong><small><span class="tag sm">${esc(LEVELS[lv].label)}</span><span>${esc(countsOf(c))}</span>${when ? `<span>${esc(when)}</span>` : ''}</small></div>
    <div class="hact"><button class="btn btn-soft sm" data-open="${esc(c.id)}">Open</button><button class="icon-btn" data-delete="${esc(c.id)}" aria-label="Delete this check">${icon('trash')}</button></div>
  </article>`;
}
const EMPTY_ART = `<svg class="empty-art" viewBox="0 0 200 140" fill="none" aria-hidden="true"><circle class="il-track-fill" cx="100" cy="70" r="56"/><circle class="il-ring" cx="100" cy="70" r="40"/><circle class="il-ring" cx="100" cy="70" r="22"/><path d="M100 46l20 8v14c0 13-8 21-20 26-12-5-20-13-20-26V54z" fill="url(#gBrand)"/><path d="M91 70l6 6 12-13" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
function renderHistory() {
  owlOnHistory();
  const area = $('#historyArea');
  if (!reports.length) {
    area.innerHTML = `<div class="card empty">${EMPTY_ART}<h3>Nothing here yet</h3><button class="btn btn-primary" data-open-scan>Check something${icon('arrow')}</button></div>`;
    return;
  }
  const query = $('#historySearch').value.trim().toLowerCase();
  const shown = reports.filter(r => {
    const lv = levelOf(r);
    const byLevel = historyFilter === 'all' || (historyFilter === 'risky' ? ['critical', 'high'].includes(lv) : lv === historyFilter);
    return byLevel && (!query || `${titleOf(asCheck(r))} ${r.label || ''} ${r.summary?.headline || ''}`.toLowerCase().includes(query));
  });
  area.innerHTML = shown.length ? shown.map(historyRow).join('') : '<div class="card empty"><h3>No matches</h3><p class="muted">Try a different search or filter.</p></div>';
}
async function loadHistory() {
  try {
    const data = await api('/scans');
    reports = data.items || [];
    updateStats(); renderHistory();
  } catch (e) {
    if (!$('#view-history').classList.contains('hidden')) $('#historyArea').innerHTML = `<div class="card empty"><h3>History is unavailable</h3><p class="muted">${esc(e.message)}</p></div>`;
  }
}

/* ───────── Scan progress ───────── */
function showProgress(heading, stages = STAGES) {
  const area = $('#progressArea');
  area.innerHTML = `<section class="card progress"><div class="p-top">${buddySvg('think')}<div class="pbody"><h3>Checking <span class="mono">${esc(heading)}</span></h3>
    <ol class="stepper">${stages.map(s => `<li class="stage" data-stage="${s.id}"><span class="sdot">${icon('check')}</span><strong>${esc(s.title)}</strong></li>`).join('')}</ol></div></div>
    <div class="game" id="game"></div></section>`;
  area.hidden = false;
  playGame($('#game'));
  const mark = (i, cls) => { const el = $(`[data-stage="${stages[i].id}"]`, area); el.classList.remove('active'); el.classList.add(cls); };
  // The server answers once, at the end, so these steps show what is happening rather than exact timing.
  mark(0, 'active');
  const timers = [
    setTimeout(() => { mark(0, 'done'); mark(1, 'active'); }, 500),
    setTimeout(() => { mark(1, 'done'); mark(2, 'active'); }, 2600),
  ];
  area.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'center' });
  return () => { timers.forEach(clearTimeout); area.hidden = true; area.innerHTML = ''; };
}

/* ───────── Mascot, game and small delights ───────── */
let sayTimer = null;
function mood(name, words, hold = 0) {
  const buddy = $('#buddyWrap .buddy');
  if (buddy) buddy.dataset.mood = name;
  const say = $('#buddySay');
  if (!say || !words) return;
  say.textContent = words; say.classList.remove('pop'); void say.offsetWidth; say.classList.add('pop');
  clearTimeout(sayTimer);
  if (hold) sayTimer = setTimeout(() => mood('idle', 'Feed me something fishy'), hold);
}
function celebrate(card) {
  if (reducedMotion || !card) return;
  const burst = document.createElement('div');
  burst.className = 'burst';
  burst.innerHTML = Array.from({ length: 22 }, (_, i) => `<i style="--x:${Math.round(Math.random() * 520 - 260)}px;--y:${Math.round(-60 - Math.random() * 190)}px;--r:${Math.round(Math.random() * 540)}deg;--d:${i * 14}ms;--c:${['#2fa870', '#8fe3b8', '#f4d35e', '#bfe8d0', '#f7b267'][i % 5]}"></i>`).join('');
  card.append(burst);
  setTimeout(() => burst.remove(), 2200);
}
let critterTimer = null;
let arenaVisible = true;
function spawnCritter() {
  const layer = $('#critters');
  if (!layer || reducedMotion || !arenaVisible || document.hidden || scanning || layer.children.length >= 2) return;
  const kinds = Object.keys(CRITTERS);
  const kind = kinds[Math.floor(Math.random() * kinds.length)];
  const el = document.createElement('button');
  el.type = 'button'; el.className = `critter cr-${kind}`; el.tabIndex = -1; el.innerHTML = CRITTERS[kind].svg;
  el.dataset.critter = kind;
  layer.append(el);
  const w = layer.clientWidth, h = layer.clientHeight;
  const rightward = Math.random() < 0.5;
  const size = el.offsetWidth;
  const y0 = h * (0.2 + Math.random() * 0.55), y1 = y0 + (Math.random() - 0.5) * h * 0.25;
  const x0 = rightward ? -size : w, x1 = rightward ? w : -size;
  el.classList.toggle('flip', !rightward);
  el._swim = el.animate([{ transform: `translate(${x0}px,${y0}px)` }, { transform: `translate(${x1}px,${y1}px)` }], { duration: 9000 + Math.random() * 5000, easing: 'linear' });
  el._swim.onfinish = () => el.remove();
}
function catchCritter(el) {
  if (el.classList.contains('caught')) return;
  el._swim?.pause();
  el.classList.add('caught');
  const lines = CRITTERS[el.dataset.critter].says;
  mood('happy', lines[Math.floor(Math.random() * lines.length)], 2400);
  const n = (Number(store.get('linkshield_caught')) || 0) + 1;
  store.set('linkshield_caught', n);
  showCaught(n, true);
  if (n % 5 === 0) celebrate($('#heroArt'));
  setTimeout(() => el.remove(), 650);
}
function showCaught(n, bump = false) {
  const pill = $('#caughtCount');
  if (!pill || !n) return;
  pill.classList.remove('hidden');
  $('b', pill).textContent = n;
  if (bump) { pill.classList.remove('bump'); void pill.offsetWidth; pill.classList.add('bump'); }
}
function startCritters() {
  if (reducedMotion) return;
  showCaught(Number(store.get('linkshield_caught')) || 0);
  new IntersectionObserver(([en]) => { arenaVisible = en.isIntersecting; }).observe($('#heroArt'));
  const loop = () => { spawnCritter(); critterTimer = setTimeout(loop, 4500 + Math.random() * 4000); };
  critterTimer = setTimeout(loop, 2500);
}
// Pick the mascot up and let go: it springs back.
function draggableBuddy() {
  const wrap = $('#buddyWrap');
  let start = null;
  wrap.addEventListener('pointerdown', e => {
    if (reducedMotion || e.button) return;
    start = { x: e.clientX, y: e.clientY, moved: false };
    wrap.setPointerCapture(e.pointerId);
    wrap.classList.add('held');
  });
  wrap.addEventListener('pointermove', e => {
    if (!start) return;
    const dx = e.clientX - start.x, dy = e.clientY - start.y;
    if (Math.hypot(dx, dy) > 6) start.moved = true;
    const pull = d => d * 0.6 / (1 + Math.abs(d) / 300); // the further you pull, the harder it resists
    wrap.style.setProperty('--dx', `${pull(dx)}px`); wrap.style.setProperty('--dy', `${pull(dy)}px`); wrap.style.setProperty('--tilt', `${Math.max(-18, Math.min(18, dx / 8))}deg`);
  });
  const drop = () => {
    if (!start) return;
    wrap.classList.remove('held');
    wrap.style.setProperty('--dx', '0px'); wrap.style.setProperty('--dy', '0px'); wrap.style.setProperty('--tilt', '0deg');
    if (start.moved) { wrap._dragged = true; mood('happy', ['Wheee!', 'Put me down!', 'Boing!'][Math.floor(Math.random() * 3)], 2200); }
    start = null;
  };
  wrap.addEventListener('pointerup', drop);
  wrap.addEventListener('pointercancel', drop);
}
// Buttons answer a press with a ripple from the finger.
function ripple(e) {
  const host = e.target.closest('.btn,.tool,.bubble,.kinds button,.chip-btn,.pick,.nav-item,.bitem,.linkbtn');
  if (!host || reducedMotion || host.disabled) return;
  const r = host.getBoundingClientRect();
  const size = Math.max(r.width, r.height) * 2.2;
  const dot = document.createElement('span');
  dot.className = 'ripple';
  dot.style.cssText = `width:${size}px;height:${size}px;left:${e.clientX - r.left - size / 2}px;top:${e.clientY - r.top - size / 2}px`;
  host.append(dot);
  dot.addEventListener('animationend', () => dot.remove());
}
const TEASE = {
  fake: 'A fake bank SMS? Feed me!', normal: 'A normal site. Bet it is fine.', otp: 'Never share an OTP!',
  disguised: "A photo that isn't a photo…", pdf: "A PDF? I'll peek inside.", rumour: 'A miracle cure? Let me check.',
};
// Sample bubbles lean toward the pointer, and the mascot comments on the one you hover.
function playfulBubbles() {
  if (reducedMotion || !window.matchMedia('(pointer: fine)').matches) return;
  $$('.arena .bubble').forEach(b => {
    b.addEventListener('pointermove', e => {
      const r = b.getBoundingClientRect();
      b.style.setProperty('--mx', `${(e.clientX - r.left - r.width / 2) * 0.22}px`);
      b.style.setProperty('--my', `${(e.clientY - r.top - r.height / 2) * 0.35}px`);
    });
    b.addEventListener('pointerenter', () => { if (!scanning) mood('idle', TEASE[b.dataset.example || b.dataset.sample], 2500); });
    b.addEventListener('pointerleave', () => { b.style.setProperty('--mx', '0px'); b.style.setProperty('--my', '0px'); });
  });
}
function playGame(root) {
  if (!root) return;
  let streak = Number(store.get('linkshield_streak')) || 0;
  let last = -1;
  const round = () => {
    let i; do { i = Math.floor(Math.random() * QUIZ.length); } while (i === last);
    last = i;
    const [real, fake, why] = QUIZ[i];
    const order = Math.random() < 0.5 ? [real, fake] : [fake, real];
    root.innerHTML = `<div class="game-head"><strong>While you wait: which one is real?</strong><span class="streak">${icon('spark')}<b>${streak}</b></span></div>
      <div class="game-pick">${order.map(a => `<button type="button" class="pick mono" data-real="${a === real ? 1 : 0}">${esc(a)}</button>`).join('')}</div><p class="game-why" hidden></p>`;
    $$('.pick', root).forEach(btn => btn.onclick = () => {
      const right = btn.dataset.real === '1';
      streak = right ? streak + 1 : 0; store.set('linkshield_streak', streak);
      $$('.pick', root).forEach(b => { b.disabled = true; b.classList.add(b.dataset.real === '1' ? 'right' : 'wrong'); });
      btn.classList.add('chosen');
      $('.streak b', root).textContent = streak;
      const out = $('.game-why', root);
      out.hidden = false; out.textContent = `${right ? 'Yes!' : 'Not quite.'} ${why}`;
      setTimeout(() => { if (root.isConnected) round(); }, right ? 1500 : 2600);
    });
  };
  round();
}

/* ───────── Report ───────── */
function summaryText(c) {
  const lv = LEVELS[levelOf(c)];
  const lines = [`LinkShield AI: ${lv.label} (${c.score}/100 triage score)`, c.summary?.headline || '', c.summary?.explanation || ''];
  partsOf(c).forEach(r => lines.push(`${isUpload(r) ? 'File' : 'Link'}: ${subject(r)} (${LEVELS[levelOf(r)].label})`));
  (c.claims || []).forEach(x => lines.push(`Claim: "${x.claim}" is ${(CLAIMS[x.verdict] || [x.verdict])[0].toLowerCase()}. ${x.explanation || ''}`));
  return [...lines, ...(c.summary?.next_steps || []), 'Note: a check cannot guarantee safety.'].filter(Boolean).join('\n');
}
function scoreSection(r) {
  const signals = r.signals || [];
  const threats = r.threats || r.web_risk?.threats || [];
  const score = Math.min(100, Number(r.score) || 0);
  const sum = signals.reduce((n, s) => n + (Number(s.weight) || 0), 0);
  const rows = signals.map((s, i) => `<details class="sig" style="--i:${i}"><summary><span class="sig-name">${esc(s.label)}<em>${esc(SOURCES[s.source] || 'Check')}</em></span><span class="bar"><i style="--w:${Math.min(100, (Number(s.weight) || 0) * 2)}%"></i></span><b>+${Number(s.weight) || 0}</b>${icon('chevron')}</summary><p>${esc(s.detail)}</p></details>`).join('');
  let total;
  if (threats.includes('KNOWN_MALWARE')) total = 'Antivirus engines already identify this exact file as malware, so the score is fixed at <b>98</b>.';
  else if (threats.length) total = `Google Web Risk lists this address (${esc(threats.join(', ').replace(/_/g, ' ').toLowerCase())}), so the score is fixed at <b>98</b>.`;
  else if (!signals.length) total = 'No warning signs added any points, so the score is <b>0</b>.';
  else total = `${signals.length} warning sign${signals.length > 1 ? 's' : ''} added <b>${sum}</b> point${sum === 1 ? '' : 's'}${sum > 90 ? ', capped at <b>90</b>' : ''}.`;
  return `<section class="card rcard wide"><h3>Why this score?</h3>
    <div class="scale"><span class="seg seg-low" style="flex:30"></span><span class="seg seg-caution" style="flex:35"></span><span class="seg seg-high" style="flex:35"></span><span class="marker" style="--at:${score}%"><b>${score}</b></span></div>
    <div class="scale-labels"><span style="flex:30"><b>0–29</b> Low</span><span style="flex:35"><b>30–64</b> Caution</span><span style="flex:35"><b>65+</b> High</span></div>
    <p class="total">${total}</p>
    ${rows ? `<div class="sigs">${rows}</div><p class="muted small">Tap a warning sign to see what it means.</p>` : `<p class="muted">${r.files?.length ? 'Finding nothing is not proof that a file is safe. A brand-new attack can hide in a normal-looking file.' : 'Finding nothing is not proof that a link is safe. Scam pages can hide from scanners.'}</p>`}
  </section>`;
}
// The download gate: whether the report clears the person to fetch or open the file.
function gateFor(r) {
  const lv = levelOf(r);
  const upload = isUpload(r);
  const link = r.files?.[0]?.source_url;
  const canLink = !upload && /^https?:\/\//i.test(link || '');
  if (!r.files?.length) return { tone: 'wait', icon: 'help', title: 'No green flag: this file could not be checked', text: r.file_error || r.sandbox?.error || 'The sandbox did not finish, so nothing is known about this file.', action: '' };
  if (lv === 'low') {
    return { tone: 'go', icon: 'shield-check', title: upload ? 'Green flag: OK to open' : 'Green flag: OK to download',
      text: upload ? 'The sandbox inspected this file and found no danger signs. Open it with your usual app.' : 'The sandbox downloaded this file for you and found no danger signs. You can download it now.',
      action: canLink ? `<a class="btn btn-go" href="${esc(link)}" target="_blank" rel="noopener noreferrer" download>${icon('download')}Download the file</a>` : '' };
  }
  if (lv === 'high' || lv === 'critical') {
    return { tone: 'stop', icon: 'shield-x', title: upload ? 'Red flag: do not open this file' : 'Red flag: download not offered',
      text: upload ? 'Delete it without opening it. If you already opened it, follow the steps above.' : 'This file shows strong danger signs, so LinkShield will not hand you a download button for it.', action: '' };
  }
  return { tone: 'wait', icon: 'alert', title: lv === 'caution' ? 'Not cleared: warning signs found' : 'Not cleared: could not be fully checked',
    text: upload ? 'Only open it if you were expecting it and trust the sender.' : 'Only download it if you were expecting it and trust the sender.',
    action: canLink ? `<button class="btn btn-soft" data-risky-download="${esc(link)}">${icon('download')}Download anyway</button>` : '' };
}
function fileSection(r) {
  if (!r.files?.length && !isUpload(r) && !r.file_expected) return '';
  const gate = gateFor(r);
  const blocked = ['high', 'critical'].includes(levelOf(r));
  const items = (r.files || []).map(f => {
    const [label, tone] = FILE_VERDICTS[f.verdict] || FILE_VERDICTS.unknown;
    const checks = (f.checks || []).map(c => `<li class="${c.ok ? 'ok' : 'bad'}">${icon(c.ok ? 'check' : 'x')}<span>${esc(c.label)}</span></li>`).join('');
    const notes = (f.notes || []).map(n => `<li>${icon('info')}<span>${esc(n)}</span></li>`).join('');
    const partial = Number(f.bytes_checked) < Number(f.size) ? ` (first ${fmtSize(f.bytes_checked)} checked)` : '';
    const sha = /^[a-f0-9]{64}$/.test(f.sha256 || '') ? f.sha256 : '';
    const rep = f.reputation || {};
    const known = rep.checked ? `<p class="rep ${rep.malicious ? 'bad' : 'ok'}">${icon(rep.malicious ? 'shield-x' : 'shield-check')}<span><b>Antivirus lookup:</b> ${rep.known
      ? `${Number(rep.malicious) || 0} of ${Number(rep.engines) || 0} engines on VirusTotal flag this exact file${rep.threat_label ? ` (${esc(rep.threat_label)})` : ''}.`
      : 'no antivirus engine has seen this exact file before.'} Only the fingerprint was sent, never the file.</span></p>` : '';
    const inside = (f.embedded_links || []).map(l => `<li class="lvl-${LEVELS[l.level] ? l.level : 'unverified'}"><span class="mono">${esc(defang(l.url))}</span><span class="tag sm">${esc((LEVELS[l.level] || LEVELS.unverified).label)}</span><small>${esc(l.reasons?.length ? l.reasons.join(', ') : l.headline || '')}</small></li>`).join('');
    const links = inside ? `<div class="inlinks"><strong>Links inside this file</strong><ul>${inside}</ul>${Number(f.links_found) > f.embedded_links.length ? `<small class="muted">${plural(Number(f.links_found), 'link')} found; the first ${f.embedded_links.length} to different websites were traced.</small>` : ''}</div>` : '';
    const verify = sha && !isUpload(r) && !blocked && crypto.subtle
      ? `<div class="verify"><label class="btn btn-ghost sm">${icon('upload')}Check my downloaded copy<input type="file" data-verify="${sha}" hidden /></label><span class="verify-out" aria-live="polite">After downloading, add your copy here to confirm it is the same file we checked. It stays on your device.</span></div>` : '';
    return `<div class="fileitem">
      <div class="filehead"><span class="ck tone-${tone === 'low' ? 'ok' : tone === 'high' ? 'danger' : tone === 'caution' ? 'warn' : 'brand'}">${icon(KIND_ICONS[f.kind] || 'file')}</span>
        <div class="filemeta"><strong class="mono">${esc(f.name)}</strong><small>${esc(f.type)} · ${esc(fmtSize(f.size))}${esc(partial)}</small></div><span class="tag lvl-${tone}">${esc(label)}</span></div>
      ${checks ? `<ul class="fchecks">${checks}</ul>` : ''}${known}${links}${notes ? `<ul class="fnotes">${notes}</ul>` : ''}
      ${sha ? `<p class="fingerprint"><span>Fingerprint (SHA-256)</span><code>${sha}</code><button class="icon-btn" data-copy="${sha}" aria-label="Copy fingerprint">${icon('copy')}</button></p>` : ''}${verify}
    </div>`;
  }).join('');
  return `<section class="card rcard wide filecard"><h3>${isUpload(r) ? 'File check' : 'File check before you download'}</h3>
    <div class="gate gate-${gate.tone}"><span class="gate-ic">${icon(gate.icon)}</span><div><strong>${esc(gate.title)}</strong><p>${esc(gate.text)}</p></div>${gate.action}</div>
    ${items}${items ? `<p class="muted small">${(r.files || []).some(f => f.opened_in_browser) ? 'Opened in the safe browser and watched. ' : ''}Never run on your device, never kept.</p>` : ''}</section>`;
}
function evidenceSection(r) {
  if (isUpload(r) || r.target === 'file') return '';
  const ev = r.sandbox?.evidence || {};
  if (r.sandbox?.status !== 'completed') {
    return `<section class="card rcard"><h3>Sandbox tests</h3><div class="soft-empty">${icon('browser')}<div><strong>The safe browser didn't run</strong><p>${esc(r.sandbox?.error || 'It is not available on this server.')}</p></div></div></section>`;
  }
  const tiles = [
    ['Redirects', ev.redirects, v => v >= 3], ['Password boxes', ev.password_inputs, v => v > 0],
    ['Downloads', ev.downloads, v => v > 0], ['Forms sent away', ev.cross_domain_forms, v => v > 0],
  ].map(([name, value, bad]) => `<div class="tile ${value == null ? '' : bad(value) ? 'bad' : 'good'}"><b>${esc(value ?? '–')}</b><span>${name}</span></div>`).join('');
  const tests = (ev.tests || []).map((t, i) => `<li class="${t.ok ? 'ok' : 'bad'}" style="--i:${i}">${icon(t.ok ? 'check' : 'x')}<span>${esc(t.label)}</span></li>`).join('');
  return `<section class="card rcard"><h3>Sandbox tests</h3><p class="muted small">Opened as an Android phone${ev.tests ? ', with time sped up 5 minutes' : ''}. Nothing was submitted or saved.</p>
    ${tests ? `<ul class="fchecks tests">${tests}</ul>` : ''}<div class="tiles">${tiles}</div></section>`;
}
function screenshotSection(r) {
  const shot = r.sandbox?.evidence?.screenshot_base64;
  const bar = `<div class="frame-bar"><i></i><i></i><i></i><span>${icon('lock')}${esc(defang(r.sandbox?.evidence?.final_url || r.url))}</span></div>`;
  if (shot && /^[A-Za-z0-9+/=]+$/.test(shot)) {
    return `<section class="card rcard"><h3>Screenshot from the safe browser</h3><p class="muted small">A picture only. You can't click anything in it. Tap to enlarge.</p><div class="frame">${bar}<img class="shot" alt="Screenshot of the page taken by the safe browser" src="data:image/jpeg;base64,${shot}"/></div></section>`;
  }
  if (r.sandbox?.evidence?.screenshot_saved) {
    return `<section class="card rcard"><h3>Screenshot from the safe browser</h3><div class="frame">${bar}<div class="frame-empty"><button class="btn btn-soft" data-load-shot="${esc(r.id)}">${icon('browser')}Load saved screenshot</button></div></div></section>`;
  }
  return '';
}
function stepsCard(steps, title) {
  if (!steps?.length) return '';
  const rows = steps.map((s, i) => {
    const [label, tone] = STATUS[s.status] || [s.status, 'off'];
    return `<li class="tstep ${tone}" style="--i:${i}"><span class="tdot">${icon(tone === 'ok' ? 'check' : tone === 'warn' ? 'x' : 'info')}</span><div><strong>${esc(s.title)}<em>${esc(label)}</em></strong><p>${esc(s.detail)}</p></div></li>`;
  }).join('');
  return `<section class="card rcard"><h3>${esc(title)}</h3><ol class="timeline">${rows}</ol></section>`;
}
// Half-width cards pair up; a leftover one spans the row.
function pairUp(cards) {
  cards = cards.filter(Boolean);
  if (cards.length % 2) cards.push(cards.pop().replace('class="card rcard"', 'class="card rcard wide"'));
  return cards.join('');
}
// One link or one file: its own verdict, score and evidence.
function partSection(r, open) {
  const lv = levelOf(r);
  const score = Math.min(100, Number(r.score) || 0);
  const wr = r.web_risk || {};
  const landed = r.sandbox?.evidence?.final_url;
  const facts = isUpload(r) ? '' : `<dl class="facts">
    ${landed && landed !== r.url ? `<div><dt>Ends up at</dt><dd class="mono">${esc(defang(landed))}</dd></div>` : ''}
    ${r.files?.length ? `<div><dt>Leads to a file</dt><dd class="mono">${esc(r.files[0].name)}</dd></div>` : ''}
    <div><dt>Google Web Risk</dt><dd>${wr.checked ? (wr.threats?.length ? esc(wr.threats.join(', ')) : 'No listed matches') : 'Not available'}</dd></div></dl>`;
  return `<details class="rpart lvl-${lv}" ${open ? 'open' : ''}>
    <summary class="part-head"><span class="ck">${icon(isUpload(r) ? 'file' : 'link')}</span><span class="part-title"><strong class="mono">${esc(subject(r))}</strong><small>${esc(r.narrative?.headline || '')}</small></span><span class="tag">${esc(LEVELS[lv].label)}</span><b class="part-score" title="Triage score out of 100">${score}</b>${icon('chevron')}</summary>
    <div class="part-body">${facts}<div class="rgrid">${fileSection(r)}${scoreSection(r)}${pairUp([evidenceSection(r), screenshotSection(r)])}</div></div>
  </details>`;
}
const KINDS = { factcheck: 'Fact-check', official: 'Official', news: 'News', other: 'Other' };
// Where a claim has been checked before: fact-checkers, official sources, what each source says, and where it started.
function traceBox(x) {
  const tr = x.trace;
  const srcs = (x.sources || []).filter(src => /^https?:\/\//i.test(src.url || '')).slice(0, 5);
  if (!tr || !srcs.length) return '';
  const lines = [tr.fact_checked ? `<li class="ok">${icon('shield-check')}<span>Fact-checked by <b>${esc(tr.fact_checkers.join(', '))}</b></span></li>` : `<li>${icon('info')}<span>No fact-checker has covered this yet</span></li>`];
  if (tr.official_sources?.length) lines.push(`<li>${icon('lock')}<span>Official sources: ${esc(tr.official_sources.join(', '))}</span></li>`);
  if (tr.origin) lines.push(`<li>${icon('globe')}<span><b>Where it started:</b> ${esc(tr.origin)}</span></li>`);
  const tally = [tr.contradicting && `${tr.contradicting} contradict it`, tr.supporting && `${tr.supporting} support it`].filter(Boolean).join(' · ');
  const chips = srcs.map((src, i) => `<a class="src src-${esc(src.kind || 'other')}" style="--i:${i}" href="${esc(src.url)}" target="_blank" rel="noopener noreferrer"><em>${esc(KINDS[src.kind] || 'Source')}</em><span>${esc(String(src.publisher || src.title || 'Source').slice(0, 40))}</span>${src.stance === 'contradicts' ? `<i class="st no" title="Contradicts the claim">${icon('x')}</i>` : src.stance === 'supports' ? `<i class="st yes" title="Supports the claim">${icon('check')}</i>` : ''}${src.published ? `<small>${esc(String(src.published).slice(0, 20))}</small>` : ''}</a>`).join('');
  return `<div class="trace"><ul>${lines.join('')}</ul>${tally ? `<p class="trace-tally">Sources: ${esc(tally)}</p>` : ''}<div class="srcs">${chips}</div></div>`;
}
function claimsSection(c) {
  if (!c.claims?.length) return '';
  const items = c.claims.map(x => {
    const [label, tone] = CLAIMS[x.verdict] || CLAIMS.unverifiable;
    const sources = (x.sources || []).filter(src => /^https?:\/\//i.test(src.url || '')).slice(0, 4)
      .map(src => `<a href="${esc(src.url)}" target="_blank" rel="noopener noreferrer">${esc(String(src.title || 'Source').slice(0, 60))}</a>`).join('');
    return `<article class="claim lvl-${tone}"><div class="claim-head"><span class="tag">${esc(x.verdict_label || label)}</span>${x.verdict_label && /[^\x00-\x7F]/.test(x.verdict_label) ? `<span class="muted small">${esc(label)}</span>` : ''}<span class="conf">${x.grounded ? `Confidence ${Math.round((Number(x.confidence) || 0) * 100)}%` : 'No sources found'}</span></div>
      <p class="claim-text">“${esc(x.claim)}”</p><p>${esc(x.explanation)}</p>${traceBox(x) || (sources ? `<div class="sources"><span>Sources</span>${sources}</div>` : '')}</article>`;
  }).join('');
  return `<section class="card rcard wide"><h3 id="claimsCard">Claims checked against sources</h3><div class="claims">${items}</div><p class="muted small">Researched with Google Search. Open the sources to judge for yourself.</p></section>`;
}
function messageSection(c) {
  const tactics = (c.tactics || []).filter(t => TACTICS[t]);
  const signs = c.message_signals || [];
  if (!tactics.length && !signs.length && !c.transcript && !c.notes?.length) return '';
  const what = c.input?.attachment?.read_as === 'audio' ? 'What the voice note says' : c.input?.attachment?.read_as === 'image' ? 'What the screenshot says' : 'The message';
  return `<section class="card rcard"><h3>How the message tries to persuade you</h3>
    ${tactics.length ? `<ul class="tactics">${tactics.map(t => `<li><b>${esc(TACTICS[t][0])}</b><span>${esc(TACTICS[t][1])}</span></li>`).join('')}</ul>` : ''}
    ${signs.length ? `<div class="sigs">${signs.map((s, i) => `<details class="sig" style="--i:${i}"><summary><span class="sig-name">${esc(s.label)}<em>${esc(SOURCES[s.source] || 'Check')}</em></span><span class="bar"><i style="--w:${Math.min(100, (Number(s.weight) || 0) * 2)}%"></i></span><b>+${Number(s.weight) || 0}</b>${icon('chevron')}</summary><p>${esc(s.detail)}</p></details>`).join('')}</div>` : ''}
    ${!tactics.length && !signs.length ? '<p class="muted">No pressure tactics or scam wording were spotted in the text.</p>' : ''}
    ${(c.notes || []).map(n => `<p class="note-line">${icon('info')}<span>${esc(n)}</span></p>`).join('')}
    ${c.transcript ? `<details class="transcript"><summary>${esc(what)}${icon('chevron')}</summary><p>${esc(c.transcript)}</p></details>` : ''}
  </section>`;
}
function stopSpeech() {
  if (!speech) return;
  if (speech.audio) { speech.audio.pause(); URL.revokeObjectURL(speech.audio.src); } else window.speechSynthesis?.cancel();
  speech.button.innerHTML = `${icon('volume')}Listen`;
  speech = null;
}
// Read the verdict aloud: Google Text-to-Speech when the server has it, otherwise the device's own voice.
async function listen(c, button) {
  if (speech) return stopSpeech();
  const text = [c.summary?.headline, c.summary?.explanation, ...(c.summary?.next_steps || [])].filter(Boolean).join('. ').slice(0, 1150);
  const language = SPEECH_LOCALES[c.language] ? c.language : 'en';
  speech = { button };
  button.innerHTML = `${icon('stop')}Stop`;
  const mine = speech;
  try {
    if (!caps?.speech) throw new Error('no server voice');
    const res = await fetch('/api/v1/tts', { method: 'POST', headers: await headers(), body: JSON.stringify({ text, language }) });
    if (!res.ok) throw new Error('no server voice');
    const audio = new Audio(URL.createObjectURL(await res.blob()));
    if (speech !== mine) return;
    speech.audio = audio; audio.onended = stopSpeech;
    await audio.play();
  } catch {
    if (speech !== mine) return;
    if (!window.speechSynthesis) { stopSpeech(); return toast('Your browser cannot read text aloud.'); }
    const say = new SpeechSynthesisUtterance(text);
    say.lang = SPEECH_LOCALES[language]; say.onend = say.onerror = () => { if (speech === mine) stopSpeech(); };
    window.speechSynthesis.cancel(); window.speechSynthesis.speak(say);
  }
}
function renderCheck(raw) {
  const c = asCheck(raw);
  stopSpeech();
  const lvKey = levelOf(c);
  const lv = LEVELS[lvKey];
  const score = Math.min(100, Number(c.score) || 0);
  const parts = partsOf(c);
  // Open the part that drives the verdict; the rest stay folded so a long report is easy to scan.
  const lead = parts.reduce((best, r) => (best && (Number(best.score) || 0) >= (Number(r.score) || 0) ? best : r), null);
  const acts = new Set((c.summary?.actions || []).map(a => a.type));
  const quick = [
    acts.has('report_cybercrime') && `<a class="btn btn-danger sm" href="https://cybercrime.gov.in" target="_blank" rel="noopener noreferrer">${icon('alert')}Report the scam</a><a class="btn btn-soft sm" href="tel:1930">${icon('phone')}Call 1930</a>`,
    acts.has('read_fact_check') && `<button class="btn btn-soft sm" data-jump="claimsCard">${icon('quote')}Read the fact-check</button>`,
    (acts.has('warn_others') || acts.has('dont_share')) && `<button class="btn btn-soft sm" data-warn>${icon('share')}Warn whoever sent it</button>`,
  ].filter(Boolean).join('');
  const advice = `<section class="card rcard"><h3>Do this now</h3><ul class="advice">${(c.summary?.next_steps || []).map(x => `<li>${icon('check')}<span>${esc(x)}</span></li>`).join('') || '<li><span>No specific advice was returned.</span></li>'}</ul>${quick ? `<div class="quick">${quick}</div>` : ''}</section>`;
  const how = stepsCard(c.steps, 'Overall') + parts.map(r => stepsCard(r.steps, subject(r))).join('');
  const area = $('#reportArea');
  area.innerHTML = `<div class="report lvl-${lvKey}">
    <div class="report-top"><div><h2>Your answer</h2><p class="muted small">${esc(countsOf(c))} · ${((Number(c.elapsed_ms) || 0) / 1000).toFixed(1)}s</p></div>
      <div class="toolbar"><button class="btn btn-soft sm" id="listenReport">${icon('volume')}Listen</button><button class="btn btn-soft sm" id="copyReport">${icon('copy')}Copy</button><button class="btn btn-soft sm" id="shareReport">${icon('share')}Warn</button><button class="btn btn-soft sm" id="downloadReport">${icon('download')}Save</button>${caps?.chat ? `<button class="btn btn-soft sm" id="askReport">${icon('msg')}Ask Shieldy</button>` : ''}<button class="btn btn-primary sm" id="scanAnother">New check</button></div></div>
    <section class="card verdict">
      <span class="verdict-buddy">${buddySvg(MOODS[lvKey][0])}</span>
      <div class="verdict-body"><span class="tag">${esc(lv.label)}</span><h2>${esc(c.summary?.headline || lv.label)}</h2><p>${esc(c.summary?.explanation || 'No explanation was returned.')}</p>
        <p class="meaning">${icon('info')}<span>${esc(lv.meaning)}</span></p></div>
      <div class="gauge"><svg viewBox="0 0 120 120"><circle class="g-track" cx="60" cy="60" r="50" pathLength="100"/><circle class="g-value" cx="60" cy="60" r="50" pathLength="100" data-to="${score * 0.75}"/></svg><div class="g-num"><strong>0</strong><small>triage score<br>out of 100</small></div></div>
    </section>
    <div class="rgrid">
      ${pairUp([advice, messageSection(c)])}
      ${claimsSection(c)}
    </div>
    ${parts.map(r => partSection(r, parts.length === 1 || r === lead)).join('')}
    ${how ? `<details class="fold"><summary>How this was checked${icon('chevron')}</summary>${how}</details>` : ''}
    <p class="disclaimer">${icon('info')}<span>${esc(c.disclaimer || 'A check is not a guarantee of safety.')}</span></p>
  </div>`;
  area.classList.remove('hidden');
  area.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
  // Kick off the gauge, marker and bar animations once the markup is in the page.
  requestAnimationFrame(() => requestAnimationFrame(() => {
    $('.report', area).classList.add('in');
    const arc = $('.g-value', area);
    arc.style.strokeDasharray = `${arc.dataset.to} 100`;
    countUp($('.g-num strong', area), score);
    if (lvKey === 'low') celebrate($('.verdict', area));
  }));
  mood(...MOODS[lvKey]);

  $('#listenReport').onclick = e => listen(c, e.currentTarget);
  $('#copyReport').onclick = async () => { try { await navigator.clipboard.writeText(summaryText(c)); toast('Summary copied'); } catch { toast('Clipboard permission denied'); } };
  $('#shareReport').onclick = () => window.open(`https://wa.me/?text=${encodeURIComponent(summaryText(c))}`, '_blank', 'noopener,noreferrer');
  $('#downloadReport').onclick = () => {
    const u = URL.createObjectURL(new Blob([JSON.stringify(raw, (key, value) => (key === 'screenshot_base64' ? undefined : value), 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = u; a.download = `linkshield-${String(c.id).slice(0, 8)}.json`; a.click();
    setTimeout(() => URL.revokeObjectURL(u), 1000);
  };
  const askBtn = $('#askReport');
  if (askBtn) askBtn.onclick = () => openChat(`Explain this LinkShield result simply and tell me what to do: "${c.summary?.headline || lv.label}" (${lv.label}, score ${score}/100) for ${titleOf(c)}.`);
  $('#scanAnother').onclick = () => {
    stopSpeech();
    area.classList.add('hidden'); area.innerHTML = ''; clearBatch();
    $('#composeText').value = ''; renderAnatomy($('#urlAnatomy'), ''); setAttachment(null);
    window.scrollTo({ top: 0, behavior: reducedMotion ? 'auto' : 'smooth' });
    mood('idle', 'What else have you got?');
    $('#composeText').focus({ preventScroll: true });
  };
}
async function loadSavedShot(button) {
  try {
    const res = await fetch(`/api/v1/scans/${encodeURIComponent(button.dataset.loadShot)}/screenshot`, { headers: await headers() });
    if (!res.ok) throw new Error('Screenshot is unavailable');
    const img = document.createElement('img');
    img.className = 'shot'; img.alt = 'Saved screenshot from the safe browser';
    img.src = URL.createObjectURL(await res.blob());
    button.parentElement.replaceChildren(img);
  } catch (e) { toast(e.message); }
}

/* ───────── The check box ───────── */
function uploadLimit() { return caps?.max_upload_bytes || 26214400; }
const fileIcon = (file, recording) => (recording ? 'mic' : /^image\//.test(file?.type || '') ? 'image' : /^audio\//.test(file?.type || '') ? 'music' : /^video\//.test(file?.type || '') ? 'video' : 'file');
// Several files can wait in the box; with more than one, each is checked on its own.
function addFiles(files, recording = false) {
  let added = 0;
  for (const file of files) {
    if (attachments.length >= MAX_BATCH) { toast(`Up to ${MAX_BATCH} things can be checked at once.`); break; }
    if (file.size > uploadLimit()) { toast(`${file.name} is too big. Files up to ${Math.round(uploadLimit() / 1048576)} MB can be checked.`); continue; }
    if (!file.size) { toast(`${file.name} is empty.`); continue; }
    attachments.push({ file, recording }); added++;
  }
  $('#fileInput').value = '';
  renderAttachments(added);
  if (added) mood('idle', recording ? 'Got your voice note.' : attachments.length > 1 ? `${attachments.length} things to sniff. Yum!` : "Got it. I won't open it.", 5000);
}
function setAttachment(file, recording = false) {
  attachments = [];
  if (file) addFiles([file], recording); else { $('#fileInput').value = ''; renderAttachments(); }
}
function renderAttachments(added = 0) {
  $('#attachChip').innerHTML = attachments.map(({ file, recording }, i) => `<div class="attach${i >= attachments.length - added ? ' new' : ''}" style="--i:${i - (attachments.length - added)}">
    <span class="ck tone-brand">${icon(fileIcon(file, recording))}</span><div><strong class="mono">${esc(recording ? 'Voice note you recorded' : file.name)}</strong><small>${esc(fmtSize(file.size))}${recording ? '' : ' · will not be opened'}</small></div><button type="button" class="icon-btn" data-remove-attachment="${i}" aria-label="Remove this attachment">${icon('x')}</button></div>`).join('');
}
async function toggleRecording() {
  const button = $('#recordBtn');
  if (recorder) return recorder.stop();
  if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) return toast('This browser cannot record. Add the voice note as a file instead.');
  let stream;
  try { stream = await navigator.mediaDevices.getUserMedia({ audio: true }); } catch { return toast('Microphone permission was not given.'); }
  const chunks = [];
  const started = Date.now();
  recorder = new MediaRecorder(stream);
  const tick = setInterval(() => {
    const secs = Math.round((Date.now() - started) / 1000);
    button.querySelector('span').textContent = `Stop · 0:${String(secs).padStart(2, '0')}`;
    if (secs >= 90) recorder?.stop(); // the server reads the first 90 seconds
  }, 500);
  recorder.ondataavailable = e => { if (e.data.size) chunks.push(e.data); };
  recorder.onstop = () => {
    clearInterval(tick);
    stream.getTracks().forEach(t => t.stop());
    const type = (recorder.mimeType || 'audio/webm').split(';')[0];
    recorder = null;
    button.classList.remove('recording'); button.innerHTML = `${icon('mic')}<span>Voice</span>`;
    if (chunks.length) addFiles([new File(chunks, `voice-note.${type.includes('mp4') ? 'm4a' : type.includes('ogg') ? 'ogg' : 'webm'}`, { type })], true);
  };
  recorder.start();
  button.classList.add('recording'); button.innerHTML = `${icon('stop')}<span>Stop · 0:00</span>`;
  if (caps && !caps.gemini_configured) toast('Voice notes are read by Gemini, which is off on this server. The recording will be noted as unread.');
}
// A harmless 256-byte stand-in for the demo: it starts like a Windows program but contains no code.
function sampleDisguisedFile() {
  const bytes = new Uint8Array(256);
  bytes.set([0x4d, 0x5a]);
  bytes.set([...'This program cannot be run in DOS mode.'].map(c => c.charCodeAt(0)), 78);
  return new File([bytes], 'holiday-photo.jpg', { type: 'image/jpeg' });
}
async function verifyCopy(input) {
  const out = input.closest('.verify').querySelector('.verify-out');
  const file = input.files?.[0];
  if (!file) return;
  out.className = 'verify-out'; out.textContent = 'Comparing on your device…';
  try {
    const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
    const hex = [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
    const same = hex === input.dataset.verify;
    out.classList.add(same ? 'ok' : 'bad');
    out.textContent = same ? 'Match. Your copy is exactly the file that was checked.' : 'No match. Your copy is NOT the file that was checked. Do not open it; check this copy as a file instead.';
  } catch { out.textContent = 'Your browser could not read that file.'; }
  input.value = '';
}
async function runCheck({ text = '', file = null, recording = false, language = null } = {}) {
  if (scanning) return;
  text = text.trim();
  if (!text && !file) { toast('Paste a message or link, or add a file first.'); return; }
  if (recorder) recorder.stop();
  scanning = true;
  go('scan');
  if (language === null) language = $('#languageInput').value;
  $('#composeText').value = text; $('#composeText').dispatchEvent(new Event('input'));
  if (attachments.length !== (file ? 1 : 0) || (file && attachments[0].file !== file)) setAttachment(file, recording);
  if (file && !attachments.length) { scanning = false; return; } // rejected for size
  clearBatch();
  const button = $('#checkBtn');
  button.disabled = true; button.innerHTML = '<span class="spinner"></span><span>Checking…</span>';
  const area = $('#reportArea');
  stopSpeech(); area.classList.add('hidden'); area.innerHTML = '';
  mood('think', 'Sniffing it out…');
  const firstLine = text.split('\n')[0];
  const stopProgress = showProgress(text && !/\s/.test(text) ? defang(text) : firstLine ? `${firstLine.slice(0, 48)}${firstLine.length > 48 ? '…' : ''}` : recording ? 'your voice note' : file.name);
  try {
    const form = new FormData();
    form.append('text', text); form.append('language', language || '');
    if (file) { form.append('file', file, file.name.slice(0, 180)); form.append('recording', recording ? '1' : ''); }
    // The short wait keeps the progress steps readable when the server answers instantly.
    const [result] = await Promise.all([api('/checks', { method: 'POST', body: form }), wait(reducedMotion ? 0 : 900)]);
    scanTimes[result.id] = Date.now(); store.set('linkshield_scan_times', JSON.stringify(scanTimes));
    stopProgress(); renderCheck(result); loadHistory();
    const unseen = result.links?.some(r => r.sandbox?.status !== 'completed');
    if (unseen) toast("Report ready. The sandbox couldn't finish visiting a link.");
    else if (result.links?.some(r => r.target === 'file')) toast('A link leads to a file. The sandbox downloaded and inspected it for you.');
  } catch (e) {
    stopProgress();
    area.innerHTML = `<section class="card error-card">${icon('alert')}<div><h3>We couldn't check that</h3><p>${esc(e.message)}</p><p class="muted small">Until it has been checked, leave it unopened.</p></div></section>`;
    area.classList.remove('hidden');
    mood('worried', "I couldn't check that.");
    toast(e.message);
  } finally {
    scanning = false;
    button.disabled = false; button.innerHTML = `${icon('shield-check')}<span>Check</span>`;
  }
}
/* ───────── Many at once ───────── */
// Several files, or a box holding only links, become one check each. A message with one file stays a single check.
function batchItems(raw) {
  const text = raw.trim();
  const words = text.split(/\s+/).filter(Boolean);
  const links = words.length > 1 && words.every(w => parseUrl(w)) ? [...new Set(words)] : [];
  if (!links.length && attachments.length <= 1) return [];
  const items = [...(links.length ? links.map(w => ({ text: w })) : text ? [{ text }] : []), ...attachments.map(a => ({ file: a.file, recording: a.recording }))];
  if (items.length > MAX_BATCH) toast(`Only the first ${MAX_BATCH} are checked at once.`);
  return items.slice(0, MAX_BATCH);
}
const itemName = it => (it.file ? (it.recording ? 'Voice note you recorded' : it.file.name) : defang(it.text));
const RANK = { critical: 4, high: 3, caution: 2, unverified: 1, low: 0 };
function clearBatch() {
  batch = [];
  const area = $('#batchArea');
  area.hidden = true; area.innerHTML = '';
}
function tallyBatch() {
  const counts = {};
  batch.forEach(b => { const k = b.result ? levelOf(b.result) : b.error ? 'failed' : null; if (k) counts[k] = (counts[k] || 0) + 1; });
  $('#batchCount').innerHTML = ['critical', 'high', 'caution', 'unverified', 'low'].filter(k => counts[k])
    .map(k => `<span class="tag lvl-${k}">${counts[k]} ${esc(LEVELS[k].label.toLowerCase())}</span>`).join('') + (counts.failed ? `<span class="tag lvl-unverified">${counts.failed} not checked</span>` : '');
}
async function runBatch(items) {
  if (scanning) return;
  if (recorder) recorder.stop();
  scanning = true;
  go('scan');
  const language = $('#languageInput').value;
  stopSpeech();
  const report = $('#reportArea');
  report.classList.add('hidden'); report.innerHTML = '';
  batch = items.map(item => ({ item }));
  const area = $('#batchArea');
  area.innerHTML = `<section class="card batch"><div class="p-top">${buddySvg('think')}<div class="pbody"><h3 id="batchTitle">Checking ${plural(items.length, 'thing')}, two at a time</h3>
    <div class="bprog"><i id="batchBar"></i></div><div class="bcount" id="batchCount"></div></div></div>
    <div class="bgrid">${batch.map((b, i) => `<button type="button" class="bitem queued" data-batch="${i}" style="--i:${i}" disabled><span class="ck">${icon(b.item.file ? fileIcon(b.item.file, b.item.recording) : 'link')}</span><span class="bmeta"><strong class="mono">${esc(itemName(b.item))}</strong><small>Waiting in line</small></span><span class="bring" style="--p:0"><b></b></span></button>`).join('')}</div>
    <p class="muted small">Every one gets all the tests. Tap a finished one to see its full report.</p></section>`;
  area.hidden = false;
  area.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
  const button = $('#checkBtn');
  button.disabled = true; button.innerHTML = '<span class="spinner"></span><span>Checking…</span>';
  $('#composeText').value = ''; $('#composeText').dispatchEvent(new Event('input')); setAttachment(null);
  mood('think', `${items.length} to sniff. On it!`);
  let next = 0, done = 0;
  const worker = async () => {
    while (next < batch.length) {
      const i = next++;
      const b = batch[i];
      const el = $(`[data-batch="${i}"]`, area);
      el.classList.replace('queued', 'running'); $('small', el).textContent = 'Checking…';
      try {
        const form = new FormData();
        form.append('text', b.item.text || ''); form.append('language', language || '');
        if (b.item.file) { form.append('file', b.item.file, b.item.file.name.slice(0, 180)); form.append('recording', b.item.recording ? '1' : ''); }
        b.result = await api('/checks', { method: 'POST', body: form });
        scanTimes[b.result.id] = Date.now();
        const lv = levelOf(b.result);
        const score = Math.min(100, Number(b.result.score) || 0);
        el.className = `bitem done lvl-${lv}`; el.disabled = false;
        $('small', el).textContent = `${LEVELS[lv].label}${b.result.summary?.headline ? ` · ${b.result.summary.headline}` : ''}`;
        $('.bring', el).style.setProperty('--p', score);
        countUp($('.bring b', el), score);
      } catch (err) {
        b.error = err.message;
        el.className = 'bitem done failed'; $('small', el).textContent = err.message;
      }
      $('#batchBar').style.width = `${(++done / batch.length) * 100}%`;
      tallyBatch();
    }
  };
  try {
    await Promise.all([worker(), worker()]);
  } finally {
    scanning = false;
    button.disabled = false; button.innerHTML = `${icon('shield-check')}<span>Check</span>`;
  }
  store.set('linkshield_scan_times', JSON.stringify(scanTimes));
  loadHistory();
  const finished = batch.filter(b => b.result);
  const worst = finished.reduce((w, b) => (!w || RANK[levelOf(b.result)] > RANK[levelOf(w.result)] ? b : w), null);
  const risky = finished.filter(b => ['critical', 'high'].includes(levelOf(b.result))).length;
  $('#batchTitle').textContent = `Checked ${plural(finished.length, 'thing')}${finished.length < batch.length ? ` (${batch.length - finished.length} could not be checked)` : ''}`;
  $('.batch .buddy', area).dataset.mood = risky ? 'alarm' : worst && levelOf(worst.result) === 'low' ? 'happy' : 'worried';
  if (risky) mood('alarm', `${risky} of them look dangerous!`);
  else if (worst && levelOf(worst.result) === 'low') { mood('happy', 'All clear this time.'); celebrate($('.batch', area)); }
  else mood('worried', 'Some need a closer look.');
  if (worst) $(`[data-batch="${batch.indexOf(worst)}"]`, area).classList.add('worst');
}
function openBatchItem(el) {
  const b = batch[Number(el.dataset.batch)];
  if (!b?.result) return;
  $$('.bitem.active').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  renderCheck(b.result);
}

// A report link from the Telegram or WhatsApp bot: /app#r=<signed code>. Show it, and keep it in this person's history.
async function openShared(token) {
  history.replaceState(null, '', location.pathname + '#scan');
  route('scan');
  mood('think', 'Fetching your report…');
  try {
    const report = await api(`/shared/${encodeURIComponent(token)}`);
    clearBatch(); $('#progressArea').hidden = true;
    if (!scanTimes[report.id]) { scanTimes[report.id] = Date.now(); store.set('linkshield_scan_times', JSON.stringify(scanTimes)); }
    renderCheck(report);
    const saved = await api(`/shared/${encodeURIComponent(token)}/save`, { method: 'POST' });
    if (saved.saved) { toast('Report from the chat saved to your history'); loadHistory(); }
  } catch (e) {
    mood('worried', "I couldn't open that report.");
    toast(e.message);
  }
}
const sharedToken = () => (location.hash.match(/^#r=([\w.-]{20,})$/) || [])[1];

// Text or a file handed over by another app through the share sheet (see sw.js), or by a /?text= link.
async function takeShared() {
  const params = new URLSearchParams(location.search);
  if (!params.has('shared') && !params.has('text')) return;
  let text = (params.get('text') || '').trim();
  let file = null;
  history.replaceState(null, '', location.pathname + '#scan');
  if (params.has('shared') && window.caches) {
    try {
      const cache = await caches.open('linkshield-shared');
      const [t, f] = await Promise.all([cache.match('/shared/text'), cache.match('/shared/file')]);
      if (t) text = (await t.text()).trim() || text;
      if (f) file = new File([await f.blob()], decodeURIComponent(f.headers.get('X-File-Name') || 'shared-file'), { type: f.headers.get('Content-Type') || '' });
      await Promise.all([cache.delete('/shared/text'), cache.delete('/shared/file')]);
    } catch { /* nothing was handed over */ }
  }
  if (text || file) runCheck({ text: text.slice(0, 6000), file });
}
function saveLanguage(value) {
  store.set('linkshield_language', value);
  api('/me', { method: 'PUT', body: JSON.stringify({ language: value }) }).catch(() => { /* kept on this device only */ });
}
async function loadPrefs() {
  const select = $('#languageInput');
  const local = store.get('linkshield_language');
  if (local !== null && [...select.options].some(o => o.value === local)) select.value = local;
  try {
    const me = await api('/me');
    if (me.language && local === null) select.value = me.language;
  } catch { /* preferences are optional */ }
}

/* ───────── Integrations and sign-in ───────── */
function renderIntegrations() {
  if (!caps) return;
  const live = [caps.webrisk_configured, caps.gemini_configured, caps.sandbox_configured].filter(Boolean).length;
  const pill = $('#cloudState');
  pill.textContent = caps.gemini_configured ? 'Google Cloud connected' : 'Local demo mode';
  pill.classList.toggle('on', live === 3); pill.classList.toggle('partial', live > 0 && live < 3);
  $('#languageInput').closest('.tool').title = caps.gemini_configured ? 'Language of the answer' : 'Other languages need Gemini, which is off on this server';
  $$('[data-needs-claims]').forEach(el => el.classList.toggle('hidden', !caps.claims));
  if (/^[A-Za-z0-9_]{4,40}$/.test(caps.telegram_bot || '')) $('#telegramSlot').innerHTML = `<a class="btn btn-soft sm" href="https://t.me/${esc(caps.telegram_bot)}" target="_blank" rel="noopener noreferrer">${icon('send')}@${esc(caps.telegram_bot)}</a>`;
  if (/^\+?[0-9]{8,15}$/.test(caps.whatsapp_bot || '')) $('#whatsappSlot').innerHTML = `<a class="btn btn-soft sm" href="https://wa.me/${esc(caps.whatsapp_bot.replace('+', ''))}" target="_blank" rel="noopener noreferrer">${icon('msg')}${esc(caps.whatsapp_bot)}</a>`;
  if (!caps.firestore) return;
  $('#historyNote').textContent = 'Saved to your account.';
}
// The account chip in the top bar: a Google profile, or a guest with a way to sign in.
function renderAccount() {
  const me = signedIn();
  const box = $('#account');
  if (caps && !caps.demo_mode && !me) return toLogin('signin');
  if (me) {
    const initial = esc((me.given_name || me.name || me.email || '?').trim()[0].toUpperCase());
    box.innerHTML = `<button type="button" class="acct-btn" id="acctBtn" aria-haspopup="true" aria-expanded="false">${me.picture ? `<img src="${esc(me.picture)}" alt="" referrerpolicy="no-referrer">` : `<span class="acct-initial">${initial}</span>`}<span class="acct-name">${esc(me.given_name || me.name || 'Account')}</span>${icon('chevron')}</button>
      <div class="acct-menu" id="acctMenu" hidden><strong>${esc(me.name || '')}</strong><small>${esc(me.email || '')}</small><p class="muted small">Your history is saved to this Google account.</p><button type="button" class="btn btn-soft sm" data-sign-out>${icon('arrow')}Sign out</button></div>`;
    $('#historyNote').textContent = 'Saved to your Google account.';
    // Checks made as a guest in this browser move into the account the first time it signs in here.
    if (store.get('ls_claimed') !== me.sub) {
      api('/me/claim-guest', { method: 'POST' }).then(r => {
        store.set('ls_claimed', me.sub);
        if (r.moved) { toast(`${plural(r.moved, 'earlier check')} moved into your account`); loadHistory(); }
      }).catch(() => { /* tried again next time */ });
    }
  } else {
    box.innerHTML = `<a class="btn btn-soft sm" href="/?signin=1" aria-label="Sign in">${icon('lock')}<span class="lbl">Sign in</span></a>`;
  }
}

/* ───────── Hoot, the history owl ───────── */
let owlTimer = null;
let owlSeen = '';
function owlSays(words, moodName = 'idle', flap = false) {
  const owl = $('#owlWrap .owl');
  if (!owl) return;
  owl.dataset.mood = moodName;
  if (flap && !reducedMotion) { owl.classList.remove('flap'); void owl.getBBox(); owl.classList.add('flap'); }
  const bubble = $('#owlSay');
  if (words) { bubble.textContent = words; bubble.classList.remove('pop'); void bubble.offsetWidth; bubble.classList.add('pop'); }
  clearTimeout(owlTimer);
  if (moodName !== 'sleep') owlTimer = setTimeout(() => { owl.dataset.mood = reports.length ? 'idle' : 'sleep'; }, 2600);
}
// The owl reacts when what is in the history changes, not on every search keystroke.
function owlOnHistory() {
  const risky = reports.filter(r => ['critical', 'high'].includes(r.level)).length;
  const key = `${reports.length}:${risky}`;
  if (key === owlSeen) return;
  owlSeen = key;
  if (!reports.length) return owlSays('Nothing yet… zzz. Check something and I will keep it.', 'sleep');
  if (risky) return owlSays(`Hoo! You dodged ${plural(risky, 'risky thing')}.`, 'alarm', true);
  owlSays(`All ${plural(reports.length, 'check')} safely filed.`, 'happy', true);
}
function owlFact() {
  if (!reports.length) return owlSays('Hoo? Nothing to show yet. Go check a link!', 'think', true);
  const risky = reports.filter(r => ['critical', 'high'].includes(r.level));
  const worst = reports.reduce((w, r) => ((Number(r.score) || 0) > (Number(w.score) || 0) ? r : w), reports[0]);
  const files = reports.filter(r => asCheck(r).uploads?.length).length;
  const facts = [
    `Your riskiest check scored ${Number(worst.score) || 0}: ${titleOf(asCheck(worst)).slice(0, 40)}.`,
    risky.length ? `${plural(risky.length, 'check')} came back risky. Glad you asked first!` : 'Not one risky check so far. Hoo-ray!',
    files ? `You checked ${plural(files, 'file')} without opening them. Wise owl move.` : 'Tip: drop a file anywhere to check it without opening it.',
    'Tap Open on any row to see its full report again.',
  ];
  owlSays(facts[Math.floor(Math.random() * facts.length)], 'happy', true);
}
function initOwl() {
  $('#owlWrap').innerHTML = owlSvg('sleep');
  const spot = $('#owlSpot');
  spot.addEventListener('click', owlFact);
  spot.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); owlFact(); } });
  $('#historySearch').addEventListener('input', e => {
    const q = e.target.value.trim();
    if (q) owlSays(`Looking for “${q.slice(0, 24)}”… ${$$('#historyArea .hrow').length} found.`, 'think');
  });
  if (reducedMotion || !window.matchMedia('(pointer: fine)').matches) return;
  document.addEventListener('pointermove', e => {
    const owl = $('#owlWrap .owl');
    if (!owl || $('#view-history').classList.contains('hidden')) return;
    const box = owl.getBoundingClientRect();
    const dx = e.clientX - (box.left + box.width / 2), dy = e.clientY - (box.top + box.height * 0.36);
    const far = Math.hypot(dx, dy) || 1, pull = Math.min(1, far / 200);
    owl.style.setProperty('--ox', (dx / far * pull).toFixed(3)); owl.style.setProperty('--oy', (dy / far * pull).toFixed(3));
  }, { passive: true });
}

/* ───────── Shieldy, the chat helper ───────── */
const CHAT_KEY = 'linkshield_chat';
let chatLog = (() => { try { return JSON.parse(sessionStorage.getItem(CHAT_KEY) || '[]'); } catch { return []; } })();
let chatImage = null; // {b64, type, url}
let chatBusy = false;
let notes = [];
const STARTERS = ['Is a KYC update SMS from my bank real?', 'I shared an OTP by mistake. What now?', 'How do I spot a fake news forward?'];
function saveChat() { try { sessionStorage.setItem(CHAT_KEY, JSON.stringify(chatLog.slice(-30))); } catch { /* private mode */ } }
function botMood(m) { $$('#fabBot .bot, #chatAvatar .bot').forEach(b => { b.dataset.mood = m; }); }
// A small, safe Markdown renderer: text is escaped first, then a few marks become tags.
function md(src) {
  const inline = s => s.replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/(^|[^*\w])\*([^*\n]+)\*(?!\w)/g, '$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  let html = '', list = null, table = [], code = null;
  const close = () => {
    if (list) { html += `</${list}>`; list = null; }
    if (table.length) {
      const rows = table.filter(r => !/^\|?\s*:?-{2,}/.test(r)).map(r => r.replace(/^\||\|$/g, '').split('|').map(c => inline(c.trim())));
      html += `<div class="md-table"><table>${rows.map((r, i) => `<tr>${r.map(c => (i ? `<td>${c}</td>` : `<th>${c}</th>`)).join('')}</tr>`).join('')}</table></div>`;
      table = [];
    }
  };
  for (const line of esc(src).split('\n')) {
    if (/^```/.test(line.trim())) { if (code === null) { close(); code = ''; } else { html += `<pre><code>${code}</code></pre>`; code = null; } continue; }
    if (code !== null) { code += line + '\n'; continue; }
    const t = line.trim();
    if (t.startsWith('|')) { if (list) { html += `</${list}>`; list = null; } table.push(t); continue; }
    if (table.length) close();
    let m;
    if ((m = t.match(/^#{1,4}\s+(.*)/))) { close(); html += `<h4>${inline(m[1])}</h4>`; } else if ((m = t.match(/^[-*•]\s+(.*)/))) { if (list !== 'ul') { close(); html += '<ul>'; list = 'ul'; } html += `<li>${inline(m[1])}</li>`; } else if ((m = t.match(/^\d+[.)]\s+(.*)/))) { if (list !== 'ol') { close(); html += '<ol>'; list = 'ol'; } html += `<li>${inline(m[1])}</li>`; } else if (!t) close();
    else { close(); html += `<p>${inline(t)}</p>`; }
  }
  if (code !== null) html += `<pre><code>${code}</code></pre>`;
  close();
  return html;
}
function chatBubble(msg, i) {
  if (msg.role === 'user') {
    const url = (msg.text.match(/(?:https?:\/\/|www\.)[^\s<>"']+/i) || [])[0];
    return `<div class="msg me" style="--i:${i}">${msg.img ? `<img class="msg-img" src="${esc(msg.img)}" alt="Your picture">` : ''}<p>${esc(msg.text)}</p>${url ? `<button type="button" class="btn btn-soft sm" data-chat-check="${esc(url)}">${icon('shield-check')}Run a full check on this link</button>` : ''}</div>`;
  }
  const sources = (msg.sources || []).map(s => `<a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.title)}</a>`).join('');
  return `<div class="msg bot-msg" style="--i:${i}"><div class="md">${md(msg.text)}</div>${sources ? `<div class="msg-src"><span>Sources</span>${sources}</div>` : ''}
    ${msg.learned ? `<div class="learned">${icon('spark')}<span>Learned: ${esc(msg.learned.text)}</span><button type="button" data-forget="${esc(msg.learned.id)}">Undo</button></div>` : ''}
    ${msg.greeting ? '' : `<div class="msg-acts"><button type="button" data-chat-listen="${i}" title="Listen">${icon('volume')}</button><button type="button" data-chat-copy="${i}" title="Copy">${icon('copy')}</button><button type="button" data-chat-like="${i}" title="Good answer: remember it">👍</button><button type="button" data-chat-fix="${i}" title="Wrong: teach the right answer">👎</button></div>`}</div>`;
}
function renderChat(suggestions = null) {
  const log = $('#chatLog');
  if (!chatLog.length) chatLog.push({ role: 'model', greeting: true, text: "Hi! I'm **Shieldy** 👋\n\nAsk me about any scam, forward or worry. I can explain things as steps, a table, or a message you can send to family. Teach me about you and I'll remember." });
  log.innerHTML = chatLog.map(chatBubble).join('');
  const sugg = suggestions || (chatLog.length <= 1 ? STARTERS : []);
  $('#chatSuggest').innerHTML = sugg.map((q, i) => `<button type="button" style="--i:${i}" data-chat-ask="${esc(q)}">${esc(q)}</button>`).join('');
  log.scrollTo({ top: log.scrollHeight, behavior: reducedMotion ? 'auto' : 'smooth' });
}
function openChat(prefill = '') {
  const panel = $('#chatPanel');
  if (panel.hidden) {
    panel.hidden = false; $('#chatFab').setAttribute('aria-expanded', 'true'); $('#chatFab').classList.add('open');
    renderChat(); loadNotes();
  }
  if (prefill) { $('#chatText').value = prefill; sendChat(); } else $('#chatText').focus({ preventScroll: true });
}
function closeChat() {
  const panel = $('#chatPanel');
  panel.classList.add('closing'); $('#chatFab').classList.remove('open'); $('#chatFab').setAttribute('aria-expanded', 'false');
  setTimeout(() => { panel.hidden = true; panel.classList.remove('closing'); }, reducedMotion ? 0 : 220);
}
async function sendChat(text = $('#chatText').value) {
  text = text.trim();
  if (!text || chatBusy) return;
  if (!caps?.chat) return toast('The chat needs Gemini, which is off on this server.');
  chatBusy = true;
  const img = chatImage;
  chatLog = chatLog.filter(m => !m.greeting);
  chatLog.push({ role: 'user', text, img: img?.url });
  $('#chatText').value = ''; $('#chatText').style.height = ''; setChatImage(null);
  renderChat([]);
  $('#chatLog').insertAdjacentHTML('beforeend', '<div class="msg bot-msg typing"><i></i><i></i><i></i></div>');
  $('#chatLog').scrollTo({ top: $('#chatLog').scrollHeight, behavior: 'smooth' });
  botMood('think'); $('#chatStatus').textContent = 'Thinking…';
  const slow = setTimeout(() => { $('#chatStatus').textContent = 'Still searching the web…'; }, 12000);
  try {
    const turns = chatLog.slice(-12).map(m => ({ role: m.role, text: m.text.slice(0, 4000) }));
    const res = await api('/chat', { method: 'POST', body: JSON.stringify({ messages: turns, image_b64: img?.b64 || null, image_type: img?.type || null }) });
    chatLog.push({ role: 'model', text: res.reply, sources: res.sources, learned: res.learned, ask: text });
    if (res.learned) { loadNotes(); toast('Shieldy learned something new'); }
    renderChat(res.suggestions); botMood('talk'); setTimeout(() => botMood('idle'), 1800);
  } catch (e) {
    chatLog.push({ role: 'model', greeting: true, text: `Sorry, ${e.message}` });
    renderChat([]); botMood('idle');
  } finally {
    clearTimeout(slow); chatBusy = false; saveChat(); $('#chatStatus').textContent = 'Ask me anything about scams and fake news';
  }
}
function setChatImage(file) {
  const box = $('#chatImage');
  if (!file) { chatImage = null; box.hidden = true; box.innerHTML = ''; return; }
  if (!/^image\//.test(file.type) || file.size > 4 * 1024 * 1024) return toast('Add a picture under 4 MB.');
  const reader = new FileReader();
  reader.onload = () => {
    const url = String(reader.result);
    chatImage = { url, b64: url.split(',')[1], type: file.type };
    box.hidden = false; box.innerHTML = `<img src="${esc(url)}" alt="Picture to ask about"><button type="button" class="icon-btn" data-chat-unimage aria-label="Remove the picture">${icon('x')}</button>`;
  };
  reader.readAsDataURL(file);
}
async function loadNotes() {
  try { notes = (await api('/chat/notes')).items || []; } catch { notes = []; }
  $('#noteCount').textContent = notes.length;
  const KIND = { fact: ['spark', 'Fact'], correction: ['alert', 'Correction'], liked: ['check', 'Good answer'] };
  $('#noteList').innerHTML = notes.length ? notes.slice().reverse().map((n, i) => `<li style="--i:${i}"><span class="ck tone-${n.kind === 'correction' ? 'warn' : n.kind === 'liked' ? 'ok' : 'brand'}">${icon(KIND[n.kind]?.[0] || 'spark')}</span><div><small>${esc(KIND[n.kind]?.[1] || 'Note')}</small><p>${esc(n.text)}</p></div><button type="button" class="icon-btn" data-forget="${esc(n.id)}" aria-label="Forget this">${icon('trash')}</button></li>`).join('')
    : '<li class="empty-note">Nothing taught yet. Try “Remember that my bank is SBI.”</li>';
}
async function teach(text, kind = 'fact') {
  try { await api('/chat/notes', { method: 'POST', body: JSON.stringify({ text, kind }) }); await loadNotes(); toast('Shieldy will remember that'); botMood('happy'); setTimeout(() => botMood('idle'), 1500); } catch (e) { toast(e.message); }
}
function chatMic() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) return toast('Voice typing is not available in this browser.');
  const rec = new SR();
  rec.lang = SPEECH_LOCALES[$('#languageInput').value] || navigator.language || 'en-IN';
  rec.interimResults = true;
  $('#chatMic').classList.add('recording');
  rec.onresult = e => { $('#chatText').value = [...e.results].map(r => r[0].transcript).join(' '); };
  rec.onend = () => { $('#chatMic').classList.remove('recording'); if ($('#chatText').value.trim()) sendChat(); };
  rec.onerror = () => toast('Could not hear you. Check the microphone permission.');
  rec.start();
}
// Clicks inside the chat panel. Returns true when it handled the click.
async function onChatClick(e) {
  const el = sel => e.target.closest(sel);
  if (el('#chatFab')) { if ($('#chatPanel').hidden) openChat(); else closeChat(); return true; }
  if (el('#chatClose')) { closeChat(); return true; }
  const tab = el('[data-chat-tab]');
  if (tab) {
    $$('[data-chat-tab]').forEach(b => b.classList.toggle('active', b === tab));
    $('#chatTalk').hidden = tab.dataset.chatTab !== 'talk'; $('#chatLearned').hidden = tab.dataset.chatTab !== 'learned';
    return true;
  }
  const askQ = el('[data-chat-ask]');
  if (askQ) { sendChat(askQ.dataset.chatAsk); return true; }
  const check = el('[data-chat-check]');
  if (check) { closeChat(); runCheck({ text: check.dataset.chatCheck }); return true; }
  if (el('[data-chat-unimage]')) { setChatImage(null); return true; }
  const forget = el('[data-forget]');
  if (forget) { try { await api(`/chat/notes/${encodeURIComponent(forget.dataset.forget)}`, { method: 'DELETE' }); chatLog.forEach(m => { if (m.learned?.id === forget.dataset.forget) delete m.learned; }); saveChat(); renderChat([]); loadNotes(); toast('Forgotten'); } catch (err) { toast(err.message); } return true; }
  const n = Number((el('[data-chat-listen],[data-chat-copy],[data-chat-like],[data-chat-fix]') || {}).dataset?.chatListen ?? el('[data-chat-copy]')?.dataset.chatCopy ?? el('[data-chat-like]')?.dataset.chatLike ?? el('[data-chat-fix]')?.dataset.chatFix);
  const msg = Number.isInteger(n) ? chatLog[n] : null;
  if (!msg) return false;
  const plain = msg.text.replace(/[*#`|>_]/g, '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');
  if (el('[data-chat-listen]')) listen({ summary: { headline: plain }, language: $('#languageInput').value }, el('[data-chat-listen]'));
  else if (el('[data-chat-copy]')) { try { await navigator.clipboard.writeText(plain); toast('Answer copied'); } catch { toast('Clipboard permission denied'); } }
  else if (el('[data-chat-like]')) { el('[data-chat-like]').classList.add('done'); teach(`Liked answer to "${(msg.ask || '').slice(0, 120)}": ${plain.slice(0, 300)}`, 'liked'); }
  else if (el('[data-chat-fix]')) {
    const holder = el('.msg');
    if (!$('.fix', holder)) {
      holder.insertAdjacentHTML('beforeend', '<form class="fix"><input maxlength="400" placeholder="What is the right answer?" aria-label="The right answer"><button class="btn btn-primary sm">Teach</button></form>');
      const form = $('.fix', holder);
      $('input', form).focus();
      form.onsubmit = ev => { ev.preventDefault(); const v = $('input', form).value.trim(); if (v) { teach(`Correction for "${(msg.ask || '').slice(0, 120)}": ${v}`, 'correction'); form.remove(); } };
    }
  }
  return true;
}
function initChat() {
  $('#fabBot').innerHTML = botSvg('idle');
  $('#chatAvatar').innerHTML = botSvg('idle');
  if (!caps?.chat) $('#chatFab').classList.add('hidden');
  const box = $('#chatText');
  box.addEventListener('input', () => { box.style.height = ''; box.style.height = `${Math.min(140, box.scrollHeight)}px`; });
  box.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); } });
  $('#chatForm').onsubmit = e => { e.preventDefault(); sendChat(); };
  $('#chatFile').addEventListener('change', e => { setChatImage(e.target.files?.[0] || null); e.target.value = ''; });
  $('#chatMic').onclick = chatMic;
  $('#teachForm').onsubmit = e => { e.preventDefault(); const v = $('#teachText').value.trim(); if (v) { teach(v); $('#teachText').value = ''; } };
  $('#forgetAll').onclick = async () => { if (!await ask('Forget everything?', 'Shieldy will forget all the notes you taught it.', 'Forget all')) return; try { await api('/chat/notes', { method: 'DELETE' }); loadNotes(); } catch (err) { toast(err.message); } };
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('#chatPanel').hidden) closeChat(); });
  // A friendly wave once, a few seconds after the page opens.
  if (caps?.chat && !reducedMotion) setTimeout(() => { if ($('#chatPanel').hidden) { $('#chatFab').classList.add('wave'); setTimeout(() => $('#chatFab').classList.remove('wave'), 3200); } }, 4000);
}

/* ───────── Page effects ───────── */
function initEffects() {
  const reveal = new IntersectionObserver(entries => entries.forEach(en => { if (en.isIntersecting) { en.target.classList.add('in'); reveal.unobserve(en.target); } }), { threshold: 0.12 });
  $$('[data-reveal]').forEach(el => reveal.observe(el));
  $('#buddyWrap').innerHTML = buddySvg('idle');
  if (!reducedMotion && window.matchMedia('(pointer: fine)').matches) {
    document.addEventListener('pointermove', e => {
      const box = $('#buddyWrap').getBoundingClientRect();
      const dx = e.clientX - (box.left + box.width / 2), dy = e.clientY - (box.top + box.height * 0.42);
      const far = Math.hypot(dx, dy) || 1, pull = Math.min(1, far / 160);
      document.documentElement.style.setProperty('--ex', (dx / far * pull).toFixed(3));
      document.documentElement.style.setProperty('--ey', (dy / far * pull).toFixed(3));
    }, { passive: true });
  }
  draggableBuddy(); playfulBubbles(); startCritters();
  document.addEventListener('pointerdown', ripple, { passive: true });
  $('#buddyWrap').addEventListener('click', () => {
    if ($('#buddyWrap')._dragged) { $('#buddyWrap')._dragged = false; return; }
    mood('happy', ['Hi!', 'That tickles.', 'Paste me a link!', 'I eat scams for breakfast.'][Math.floor(Math.random() * 4)], 2600); });
  const bar = $('.topbar');
  const onScroll = () => bar.classList.toggle('scrolled', window.scrollY > 8);
  window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
}

// A sample bubble flies into the mascot before its check starts.
async function feed(bubble) {
  if (reducedMotion || scanning || !bubble.classList.contains('bubble') || getComputedStyle(bubble).position !== 'absolute') return;
  const from = bubble.getBoundingClientRect(), to = $('#buddyWrap').getBoundingClientRect();
  bubble.style.setProperty('--fx', `${Math.round(to.left + to.width / 2 - from.left - from.width / 2)}px`);
  bubble.style.setProperty('--fy', `${Math.round(to.top + to.height * 0.55 - from.top - from.height / 2)}px`);
  bubble.classList.add('eaten');
  await wait(420);
  $('#buddyWrap').classList.add('chomp');
  setTimeout(() => { bubble.classList.remove('eaten'); $('#buddyWrap').classList.remove('chomp'); }, 900);
}

// Expanding sections slide open and shut instead of jumping.
function smoothDetails(e) {
  const summary = e.target.closest('summary');
  const details = summary?.parentElement;
  if (!details || details.tagName !== 'DETAILS' || reducedMotion || e.target.closest('a,button,input,label')) return;
  e.preventDefault();
  if (details._anim) return;
  const opening = !details.open;
  const from = details.getBoundingClientRect().height;
  details.open = !details.open;
  const to = details.getBoundingClientRect().height;
  details.open = true;
  details.classList.toggle('closing', !opening);
  details.style.overflow = 'hidden';
  const anim = details._anim = details.animate({ height: [`${from}px`, `${to}px`] }, { duration: Math.min(420, 160 + Math.abs(to - from) * 0.35), easing: 'cubic-bezier(.2,.8,.2,1)' });
  anim.onfinish = anim.oncancel = () => {
    details._anim = null; details.style.overflow = ''; details.classList.remove('closing');
    if (!opening) details.open = false;
  };
}
const KIND_HINTS = {
  link: 'Paste the link in the box.', image: 'Pick the screenshot.',
  chat: 'In WhatsApp: open the chat → ⋮ → More → Export chat, then pick the file here.',
};
function pickKind(kind) {
  const input = $('#fileInput');
  if (kind === 'voice') return toggleRecording();
  if (kind === 'link') { $('#composeText').focus(); return toast(KIND_HINTS.link); }
  input.accept = kind === 'image' ? 'image/*' : kind === 'chat' ? '.txt,.zip,text/plain,application/zip' : '';
  if (kind === 'many') toast(`Pick up to ${MAX_BATCH} files, or paste several links in the box.`);
  if (KIND_HINTS[kind]) toast(KIND_HINTS[kind]);
  input.click();
  setTimeout(() => { input.accept = ''; }, 1000);
}

async function onClick(e) {
  if (await onChatClick(e)) return;
  const jump = e.target.closest('[data-jump]');
  if (jump) return document.getElementById(jump.dataset.jump)?.closest('.card')?.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'center' });
  if (e.target.closest('[data-warn]')) return $('#shareReport')?.click();
  const viewBtn = e.target.closest('[data-view]');
  if (viewBtn) return go(viewBtn.dataset.view);
  if (e.target.closest('[data-open-scan]')) { go('scan'); return $('#composeText').focus(); }
  if (e.target.closest('[data-sign-out]')) { try { localStorage.removeItem(TOKEN_KEY); } catch { /* private mode */ } return location.replace('/?out=1'); }
  const acct = e.target.closest('#acctBtn');
  const menu = $('#acctMenu');
  if (menu && !e.target.closest('#acctMenu')) {
    const open = !!acct && menu.hidden;
    menu.hidden = !open; $('#acctBtn').setAttribute('aria-expanded', open);
    if (acct) return;
  }
  const critter = e.target.closest('[data-critter]');
  if (critter) return catchCritter(critter);
  const rm = e.target.closest('[data-remove-attachment]');
  if (rm) {
    rm.closest('.attach')?.classList.add('leaving');
    await wait(reducedMotion ? 0 : 220);
    attachments.splice(Number(rm.dataset.removeAttachment) || 0, 1);
    return renderAttachments();
  }
  const bitem = e.target.closest('[data-batch]');
  if (bitem) return openBatchItem(bitem);
  if (e.target.closest('#recordBtn')) return toggleRecording();
  const shot = e.target.closest('[data-load-shot]');
  if (shot) return loadSavedShot(shot);
  if (e.target.closest('[data-channels]')) return $('#channelDialog').showModal();
  const kind = e.target.closest('[data-kind]');
  if (kind) return pickKind(kind.dataset.kind);
  const sample = e.target.closest('[data-sample]');
  if (sample) { await feed(sample); return runCheck({ file: sampleDisguisedFile() }); }
  const copy = e.target.closest('[data-copy]');
  if (copy) { try { await navigator.clipboard.writeText(copy.dataset.copy); toast('Fingerprint copied'); } catch { toast('Clipboard permission denied'); } return; }
  const risky = e.target.closest('[data-risky-download]');
  if (risky) {
    if (await ask('Download a file that was not cleared?', 'LinkShield could not give this file a green flag. Only continue if you were expecting it and trust the sender.', 'Download anyway')) window.open(risky.dataset.riskyDownload, '_blank', 'noopener,noreferrer');
    return;
  }
  const example = e.target.closest('[data-example]');
  if (example) { await feed(example); return runCheck({ text: EXAMPLES[example.dataset.example] }); }
  const paste = e.target.closest('[data-paste]');
  if (paste) {
    const input = $('#' + paste.dataset.paste);
    try {
      const text = await navigator.clipboard.readText();
      if (!text.trim()) return toast('Your clipboard is empty.');
      input.value = text.trim().slice(0, 6000); input.dispatchEvent(new Event('input')); input.focus();
    } catch { input.focus(); toast('Paste is blocked here. Press Ctrl+V or ⌘V instead.'); }
    return;
  }
  const filter = e.target.closest('[data-filter]');
  if (filter) {
    historyFilter = filter.dataset.filter;
    owlSays({ all: 'Showing everything I kept.', risky: 'Only the scary ones. Brr.', caution: 'These needed a closer look.', low: 'The calm ones.', unverified: "The ones I couldn't see well." }[historyFilter] || '', 'think');
    $$('[data-filter]').forEach(b => b.classList.toggle('active', b === filter));
    return renderHistory();
  }
  const open = e.target.closest('[data-open]');
  if (open) {
    try { const r = await api(`/scans/${encodeURIComponent(open.dataset.open)}`); go('scan'); $('#progressArea').hidden = true; clearBatch(); renderCheck(r); } catch (err) { toast(err.message); }
    return;
  }
  const del = e.target.closest('[data-delete]');
  if (del) {
    if (!await ask('Delete this report?', 'It will be removed from your history.')) return;
    try {
      del.closest('.hrow')?.classList.add('leaving');
      await Promise.all([api(`/scans/${encodeURIComponent(del.dataset.delete)}`, { method: 'DELETE' }), wait(reducedMotion ? 0 : 220)]);
      loadHistory(); toast('Report deleted'); owlSays('Shredded it!', 'happy', true);
    } catch (err) { toast(err.message); loadHistory(); }
    return;
  }
  if (e.target.closest('.shot')) { $('#lightbox img').src = e.target.closest('.shot').src; return $('#lightbox').classList.remove('hidden'); }
  if (e.target.closest('#lightbox')) $('#lightbox').classList.add('hidden');
}

async function init() {
  route(location.hash.slice(1) || 'scan');
  window.addEventListener('hashchange', () => { const t = sharedToken(); if (t) openShared(t); else route(location.hash.slice(1)); });
  document.addEventListener('click', onClick);
  document.addEventListener('click', smoothDetails);
  // Drop a file anywhere on the page.
  let dragDepth = 0;
  const overlay = $('#dropOverlay');
  const hasFiles = e => [...(e.dataTransfer?.types || [])].includes('Files');
  document.addEventListener('dragenter', e => { if (!hasFiles(e)) return; dragDepth++; overlay.classList.add('show'); });
  document.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; overlay.classList.remove('show'); } });
  document.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
  document.addEventListener('drop', e => {
    if (!hasFiles(e)) return;
    e.preventDefault(); dragDepth = 0; overlay.classList.remove('show');
    const files = [...(e.dataTransfer.files || [])];
    if (!files.length) return;
    go('scan'); addFiles(files);
    $('#checkForm').scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'center' });
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') $('#lightbox').classList.add('hidden');
    if (e.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) { e.preventDefault(); go('scan'); $('#composeText').focus(); }
  });
  smartInput($('#composeText'), $('#urlAnatomy'));
  $('#composeText').addEventListener('input', e => { if (!scanning && e.target.value.trim().length > 3) mood('idle', 'Ooh. Press Check!'); });
  $('#checkForm').onsubmit = e => {
    e.preventDefault();
    const items = batchItems($('#composeText').value);
    if (items.length > 1) return runBatch(items);
    runCheck({ text: $('#composeText').value, file: attachments[0]?.file || null, recording: !!attachments[0]?.recording });
  };
  $('#fileInput').addEventListener('change', e => addFiles([...(e.target.files || [])]));
  $('#languageInput').addEventListener('change', e => saveLanguage(e.target.value));
  // A screenshot copied to the clipboard can be pasted straight into the box.
  $('#composeText').addEventListener('paste', e => { const files = [...(e.clipboardData?.files || [])]; if (files.length) { e.preventDefault(); addFiles(files); } });
  document.addEventListener('change', e => { if (e.target.matches('[data-verify]')) verifyCopy(e.target); });
  $('#historySearch').addEventListener('input', renderHistory);
  $('#clearHistory').onclick = async () => {
    if (!reports.length) return toast('Your history is already empty.');
    if (!await ask('Clear your whole history?', 'All your saved LinkShield reports will be deleted.', 'Clear all')) return;
    try { await api('/scans', { method: 'DELETE' }); loadHistory(); toast('History cleared'); owlSays('All gone. Time for a nap…', 'sleep'); } catch (e) { toast(e.message); }
  };
  initEffects(); initOwl();
  window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); installPrompt = e; $('#installBtn').classList.remove('hidden'); $('#installHint').classList.add('hidden'); });
  $('#installBtn').onclick = async () => { if (!installPrompt) return; installPrompt.prompt(); await installPrompt.userChoice; installPrompt = null; $('#installBtn').classList.add('hidden'); };
  // The service worker receives things shared from other apps; it needs HTTPS (or localhost).
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => { /* sharing from other apps stays off */ });
  try { caps = await (await fetch('/api/v1/capabilities')).json(); renderIntegrations(); renderAccount(); } catch { toast('Unable to load integration status'); }
  initChat();
  if (caps?.demo_mode) loadPrefs();
  takeShared();
  if (sharedToken()) openShared(sharedToken());
}
init();
