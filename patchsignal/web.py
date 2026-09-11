"""Upload a CSV, get the replay page. The whole web demo."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, Form, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .engine import run_replay
from .inventory import OPTIONAL, REQUIRED, InventoryError
from .state import ACTIONS, StateStore

app = FastAPI(title="PatchSignal demo")
_store = StateStore("out/state.json")


def configure(state_path: str | Path) -> None:
    global _store
    _store = StateStore(state_path)


class Act(BaseModel):
    key: str
    action: str
    by: str = ""
    note: str = ""


@app.post("/act")
def act(a: Act) -> JSONResponse:
    if a.action not in ACTIONS:
        return JSONResponse({"ok": False, "error": f"unknown action; use one of {', '.join(ACTIONS)}"}, status_code=400)
    rec = _store.record(a.key, a.action, a.by, a.note)
    return JSONResponse({"ok": True, "state": {"action": rec.action, "by": rec.by, "note": rec.note, "at": rec.at, "sentence": rec.sentence}})

FORM = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PatchSignal</title>
<style>:root{--bg:#f7f7f5;--card:#fff;--soft:#f1f1ee;--ink:#1c1c1a;--muted:#6b6b66;--line:#e4e4df;--errbg:#fdecea;--errline:#f5c2c0;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--bg:#141412;--card:#1e1e1b;--soft:#2a2a26;--ink:#ecebe6;--muted:#a09f98;--line:#33332f;--errbg:#3a1d1a;--errline:#6b2f2a;color-scheme:dark}}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif;padding:32px 16px}
main{max-width:560px;margin:0 auto;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px}
h1{font-size:22px;margin:0 0 6px}p{margin:0 0 16px;color:var(--muted)}label{display:block;font-weight:600;margin:14px 0 6px}
input,select{font:inherit;padding:8px;border:1px solid var(--line);border-radius:8px;width:100%;box-sizing:border-box;background:var(--bg);color:var(--ink)}
button{margin-top:18px;font:inherit;font-weight:600;background:var(--ink);color:var(--bg);border:0;border-radius:8px;padding:10px 18px;cursor:pointer}
code{font-size:13px;background:var(--soft);padding:1px 5px;border-radius:4px}.err{background:var(--errbg);border:1px solid var(--errline);border-radius:8px;padding:10px;margin-bottom:12px}</style></head>
<body><main><h1>PatchSignal</h1><p>Upload your technology list. See exactly which exploited vulnerabilities would have reached whom, and which ones stayed quiet.</p>
@@ERROR@@
<form method="post" action="/replay" enctype="multipart/form-data">
<label>Inventory CSV</label><input type="file" name="inventory" accept=".csv,text/csv" required>
<label>Look back</label><select name="days"><option value="30">30 days</option><option value="90" selected>90 days</option><option value="180">180 days</option><option value="365">365 days</option></select>
<label>Fallback contact for assets with no owner</label><input type="email" name="fallback" value="security@example.com">
<button type="submit">Run the replay</button></form>
<p style="margin-top:20px;font-size:14px">Required columns: @@REQUIRED@@. Optional: @@OPTIONAL@@.</p>
</main></body></html>"""


def _form(error: str = "") -> str:
    # str.format is not used here: the CSS braces would collide with it.
    return (
        FORM.replace("@@ERROR@@", f'<div class="err">{error}</div>' if error else "")
        .replace("@@REQUIRED@@", ", ".join(f"<code>{c}</code>" for c in REQUIRED))
        .replace("@@OPTIONAL@@", ", ".join(f"<code>{c}</code>" for c in OPTIONAL))
    )


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return _form()


@app.post("/replay", response_class=HTMLResponse)
async def replay(inventory: UploadFile = File(...), days: int = Form(90), fallback: str = Form("security@example.com")) -> str:
    raw = await inventory.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return _form("That file is not UTF-8 text. Export it from your spreadsheet as CSV (UTF-8).")
    try:
        r = run_replay(text, inventory_name=inventory.filename or "inventory.csv", days=days, fallback_email=fallback, state=_store)
    except InventoryError as e:
        return _form(str(e))
    return r.html
