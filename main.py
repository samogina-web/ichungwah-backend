# main.py  — minimal, known-good
import os
import hmac
import hashlib
import re
from typing import List, Optional, Literal

import requests
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
MODE = os.getenv("MODE", "observe")  # "observe" or "active"

app = FastAPI(title="Ichung'wah Moderation & Monitoring MVP")

# CORS (allow all for MVP; restrict later)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === RULES (safe minimal set) ===
BLOCKLIST_REGEX = [
    re.compile(r"(?i)kill"),
    re.compile(r"(?i)lynch"),
    re.compile(r"(?i)burn"),
    re.compile(r"(?i)attack"),
]
WATCHLIST_REGEX = [
    re.compile(r"(?i)finance bill"),
    re.compile(r"(?i)tax"),
]
SLUR_PATTERNS = [
    re.compile(r"(?i)slur1"),  # placeholder
    re.compile(r"(?i)slur2"),  # placeholder
]

# === MODELS ===
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

# === HELPERS ===
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
        return DecideOut(action="REVIEW" if matches_block else "ALLOW", score=tox,
                         rule_matches=matches_block + matches_watch)

    # hard delete if violent or doxxing pattern appears (doxxing not in minimal set yet)
    if any(re.search(r"(?i)kill|lynch|burn|attack", m) for m in matches_block):
        return DecideOut(action="DELETE", score=max(0.9, tox), rule_matches=matches_block)

    if tox >= 0.90: return DecideOut(action="DELETE", score=tox, rule_matches=matches_block + matches_watch)
    if tox >= 0.70 or matches_block: return DecideOut(action="HIDE", score=max(0.7, tox),
                                                      rule_matches=matches_block + matches_watch)
    if tox >= 0.40 or matches_watch: return DecideOut(action="REVIEW", score=max(0.4, tox),
                                                      rule_matches=matches_block + matches_watch)
    return DecideOut(action="ALLOW", score=tox, rule_matches=matches_block + matches_watch)

# (FB helpers kept for later)
def fb_headers():
    return {"Authorization": f"Bearer {PAGE_ACCESS_TOKEN}"}

def fb_hide_comment(comment_id: str):
    url = f"{GRAPH_BASE}/{comment_id}"
    return requests.post(url, params={"is_hidden": "true"}, headers=fb_headers())

def fb_delete_comment(comment_id: str):
    url = f"{GRAPH_BASE}/{comment_id}"
    return requests.delete(url, headers=fb_headers())

# === ROUTES ===
@app.get("/health")
async def health():
    return {"ok": True, "mode": MODE}

# Simple browser demo page
@app.get("/demo", response_class=HTMLResponse)
async def demo():
    return """
    <!doctype html><meta charset="utf-8" />
    <title>Moderation Demo</title>
    <div style="max-width:700px;margin:2rem auto;font-family:system-ui">
      <h1>Moderation Demo</h1>
      <p>Type a sample comment and click Decide.</p>
      <textarea id="t" rows="7" style="width:100%;padding:.75rem;border:1px solid #ddd;border-radius:12px"></textarea>
      <div style="margin:.75rem 0">
        <button id="b" style="padding:.6rem 1rem;border:0;border-radius:10px;background:#111;color:#fff">Decide</button>
      </div>
      <pre id="out" style="background:#fafafa;border:1px solid #eee;padding:1rem;border-radius:12px;white-space:pre-wrap"></pre>
      <script>
        const KEY = "dev-key";
        document.getElementById("b").onclick = async () => {
          const text = document.getElementById("t").value;
          const res = await fetch("/decide",{
            method:"POST",
            headers:{"Content-Type":"application/json","X-API-Key":KEY},
            body:JSON.stringify({text,actor:{}})
          });
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

# Webhook stubs (safe to leave)
@app.get("/webhook/facebook")
async def verify(mode: str = None, challenge: str = None, verify_token: str = None):
    if mode == "subscribe" and verify_token == VERIFY_TOKEN:
        return challenge
    raise HTTPException(status_code=403, detail="Verification failed")

@app.post("/webhook/facebook")
async def webhook(req: Request, x_hub_signature_256: Optional[str] = Header(None)):
    body = await req.body()
    if APP_SECRET:
        expected = 'sha256=' + hmac.new(APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if x_hub_signature_256 != expected:
            raise HTTPException(status_code=401, detail="Bad signature")
    return {"status": "ok"}
