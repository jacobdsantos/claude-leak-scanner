"""FastAPI application — dashboard, scan API, SSE streaming."""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

import config
import db
from models import ScanProgress
from scanner import run_scan


# ── State ────────────────────────────────────────────────────────────────────

_scan_lock = asyncio.Lock()
_scan_running = False
_progress_queues: list[asyncio.Queue] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB on startup
    database = await db.get_db()
    await database.close()
    yield


app = FastAPI(title="Claude Code Lure Monitor", lifespan=lifespan)

# Static files and templates
static_dir = Path(__file__).parent / "static"
templates_dir = Path(__file__).parent / "templates"
static_dir.mkdir(exist_ok=True)
templates_dir.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
templates = Jinja2Templates(directory=str(templates_dir))


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    database = await db.get_db()
    try:
        stats = await db.get_stats(database)
        findings = await db.get_findings(database)
        scans = await db.get_scans(database, limit=10)
    finally:
        await database.close()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "stats": stats,
        "findings": findings,
        "scans": scans,
        "platforms": config.ENABLED_PLATFORMS,
        "scan_running": _scan_running,
    })


# ── Scan API ─────────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def trigger_scan(request: Request):
    global _scan_running

    if _scan_running:
        return JSONResponse({"status": "already_running"}, status_code=409)

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    platforms = body.get("platforms", config.ENABLED_PLATFORMS)
    days_back = body.get("days_back", config.DAYS_BACK)

    async def run_in_background():
        global _scan_running
        _scan_running = True
        try:
            async def progress_cb(progress: ScanProgress):
                data = json.dumps(progress.model_dump())
                for q in _progress_queues:
                    await q.put(data)

            total, new = await run_scan(
                platforms=platforms,
                days_back=days_back,
                progress_callback=progress_cb,
            )

            # Send completion event
            done_data = json.dumps({
                "platform": "all",
                "status": "complete",
                "found": total,
                "message": f"Scan complete: {total} findings ({new} new)",
            })
            for q in _progress_queues:
                await q.put(done_data)

        except Exception as e:
            err_data = json.dumps({
                "platform": "all",
                "status": "error",
                "found": 0,
                "message": f"Scan failed: {e}",
            })
            for q in _progress_queues:
                await q.put(err_data)
        finally:
            _scan_running = False

    asyncio.create_task(run_in_background())
    return JSONResponse({"status": "started", "platforms": platforms})


@app.get("/api/scan/stream")
async def scan_stream():
    """SSE endpoint for live scan progress."""
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues.append(queue)

    async def event_generator():
        try:
            while True:
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30)
                    yield f"data: {data}\n\n"
                    # Check if scan is complete
                    parsed = json.loads(data)
                    if parsed.get("status") in ("complete", "error"):
                        break
                except asyncio.TimeoutError:
                    yield f"data: {json.dumps({'platform': 'heartbeat', 'status': 'waiting', 'found': 0, 'message': ''})}\n\n"
        finally:
            _progress_queues.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Data API ─────────────────────────────────────────────────────────────────

@app.get("/api/findings")
async def get_findings(
    platform: str | None = None,
    severity: str | None = None,
    new_only: bool = False,
    include_dismissed: bool = False,
):
    database = await db.get_db()
    try:
        findings = await db.get_findings(
            database, platform=platform, severity=severity,
            new_only=new_only, include_dismissed=include_dismissed,
        )
    finally:
        await database.close()

    return [f.model_dump() for f in findings]


@app.post("/api/findings/{finding_id:path}/dismiss")
async def dismiss_finding(finding_id: str):
    database = await db.get_db()
    try:
        await db.dismiss_finding(database, finding_id)
    finally:
        await database.close()
    return {"status": "dismissed"}


@app.get("/api/scans")
async def get_scans():
    database = await db.get_db()
    try:
        scans = await db.get_scans(database, limit=20)
    finally:
        await database.close()
    return [s.model_dump() for s in scans]


@app.get("/api/stats")
async def get_stats():
    database = await db.get_db()
    try:
        stats = await db.get_stats(database)
    finally:
        await database.close()
    return stats.model_dump()


# ── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=config.DASHBOARD_PORT,
        reload=True,
    )
