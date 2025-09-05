# main.py
import os, hmac, hashlib, re, requests
from typing import List, Optional, Literal
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# === ENV ===
PAGE_ACCESS_TOKEN = os.getenv("PAGE_ACCESS_TOKEN", "")
APP_SECRET = os.getenv("APP_SECRET", "")
VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "dev-verify")
GRAPH_BASE = os.getenv("GRAPH_BASE", "https://graph.facebook.com/v19.0")
PAGE_ID = os.getenv("PAGE_ID", "")
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "dev-key")
MODE = os.getenv("MODE", "observe")  # "observe" (safe) or "active"

app = FastAPI(title="Ichung'wah Moderation & Monitoring MVP")

# Allow calls from anywhere (we’ll lock later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === RULES ===
BLOCKLIST_REGEX = [
    re.compile(r"(?i)\b(kill|lynch|burn|shoot|stone|attack|beat)\b.{0,18}\b(him|her|them|you|ichung[w]ah|majority\s*leader|mp)\b"),
    re.compile(r"(?i)\bhang\b.{0,18}\b(him|her|them|you|ichung[w]ah)\b"),
    re.compile(r"\b(07|01)\d{8}\b"),  # KE phone
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),  # email
    re.compile(r"(?i)\bmadoadoa\b"),
    re.compile(r"(?i)\b(bit\.ly|tinyurl\.com|ow\.ly|buff\.ly|t\.co|goo\.gl|smarturl\.it)\b"),
    re.compile(r"(?i)\bDM (me|now) for profits\b|\bWhatsApp\b.{0,12}\bprofits\b|\bmpesa\b.{0,12}\b(double|multiply)\b"),
]

WATCHLIST_REGEX = [
    re.compile(r"(?i)handshake|deep state|state capture|finance bill|tax hike|UDA|Azimio|bi-partisan|public participation"),
    re.compile(r"(?i)(is|are|was|were)\s+(a|an)\s+(thief|corrupt|liar|traitor)")
]

SLUR_PATTERNS = [
    re.compile(r"(?i)\b[k*]w[a@]***\b"),
    re.compile(r"(?i)\b[jg]***[t7]\b"),
]

class ActorMeta(BaseModel):
    user_id: Optional[str] = None
    is_new_account: Optional[bool] = None
    is_whitelisted: Optional[bool] = None

Action = Literal["ALLOW", "REVIEW", "HIDE", "DELETE"]

class DecideIn(BaseModel):
    text: str
    actor: ActorMeta = ActorMeta()
    context: Optional[dict] = None

class DecideOut(BaseModel):
    action: Action
    score: float
    rule_matches: List[str]

def rule_hit(text: str, patterns: List[re.Pattern]) -> List[str]:
    return [pat.pattern for pat in patterns if pat.search(text)]

def naive_toxicity_score(text: str) -> float:
    t = text.lower()
    s = 0.0
    if len(text) > 200: s += 0.05
    if sum(1 for c in text if c.isupper()) > 20: s += 0.1
    if "!!!" in text or "???" in text: s += 0.1
    if rule_hit(t, SLUR_PATTERNS): s += 0.5
    if rule_hit(t, BLOCKLIST_REGEX): s += 0.4
    return min(s, 1.0)

def decide(text: str, actor: ActorMeta) -> DecideOut:
    matches_block = rule_hit(text, BLOCKLIST_REGEX) + rule_hit(text, SLUR_PATTERNS)
    matches_watch = rule_hit(text, WATCHLIST_REGEX)
    tox = naive_toxicity_score(text)

    if actor.is_whitelisted:
        return DecideOut(action="REVIEW" if matches_block else "ALLOW", score=tox, rule_matches=matches_block + matches_watch)

    if any(re.search(r"(?i)kill|lynch|burn|shoot|hang|attack", m) for m in matches_block) or re.search(r"\b(07|01)\d{8}\b", text):
        return DecideOut(action="DELETE", score=max(0.9, tox), rule_matches=matches_block)

    if tox >= 0.90: return DecideOut(action="DELETE", score=tox, rule_matches=matches_block + matches_watch)
    if tox >= 0.70 or matches_block: return DecideOut(action="HIDE", score=max(0.7, tox), rule_matches=matches_block + matches_watch)
    if tox >= 0.40 or matches_watch: return DecideOut(action="REVIEW", score=max(0.4, tox), rule_matches=matches_block + matches_watch)
    return DecideOut(action="ALLOW", score=tox, rule_matches=matches_block + matches_watch)

def fb_headers():
    return {"Authorization": f"Bearer {PAGE_ACCESS_TOKEN}"}

def fb_hide_comment(comment_id: str):
    import requests
    url = f"{GRAPH_BASE}/{comment_id}"
    return requests.post(url, params={"is_hidden": "true"}, headers=fb_headers())

def fb_delete_comment(comment_id: str):
    import requests
    url = f"{GRAPH_BASE}/{comment_id}"
    return requests.delete(url, headers=fb_headers())

@app.get("/health")
async def health(): return {"ok": True, "mode": MODE}

# tiny browser demo page so you can test without any tools
@app.get("/demo", response_class=HTMLResponse)
async def demo():
    return """
    <!doctype html><meta charset="utf-8" />
    <title>Moderation Demo</title>
    <div style="max-width:700px;margin:2rem auto;font-family:system-ui">
      <h1>Moderation Demo</h1>
      <p>Type a sample Facebook comment, click Decide.</p>
      <textarea id="t" rows="7" style="width:100%;padding:.75rem;border:1px solid #ddd;border-radius:12px"></textarea>
      <div style="margin:.75rem 0">
        <button id="b" style="padding:.6rem 1rem;border:0;border-radius:10px;background:#111;color:#fff">Decide</button>
        <small id="hint" style="margin-left:.5rem;color:#666"></small>
      </div>
      <pre id="out" style="background:#fafafa;border:1px solid #eee;padding:1rem;border-radius:12px;white-space:pre-wrap"></pre>
      <script>
        const KEY = "dev-key"; // must match INTERNAL_API_KEY on the server
        document.getElementById("b").onclick = async () => {
          const text = document.getElementById("t").value;
          const res = await fetch("/decide",{method:"POST",headers:{"Content-Type":"application/json","X-API-Key":KEY},body:JSON.stringify({text,actor:{}})});
          document.getElementById("out").textContent = await res.text();
        };
      </script>
    </div>
    """

@app.post("/decide")
async def decide_api(payload: DecideIn, x_api_key: str = Header("")):
    if x_api_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Bad API key")
    return decide(payload.text, payload.actor)

# (Optional) Facebook webhook endpoints (safe to leave; unused until you connect Meta)
@app.get("/webhook/facebook")
async def verify(mode: str = None, challenge: str = None, verify_token: str = None):
    if mode == "subscribe" and verify_token == VERIFY_TOKEN: return challenge
    raise HTTPException(status_code=403, detail="Verification failed")

@app.post("/webhook/facebook")
async def webhook(req: Request, x_hub_signature_256: Optional[str] = Header(None)):
    body = await req.body()
    if APP_SECRET:
        expected = 'sha256=' + hmac.new(APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if x_hub_signature_256 != expected:
            raise HTTPException(status_code=401, detail="Bad signature")
    # just acknowledge for now
    return {"status":"ok"}
