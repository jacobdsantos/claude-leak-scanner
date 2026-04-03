"""FastAPI application — dashboard, scan API, SSE streaming, auto-scheduler."""

from __future__ import annotations

import asyncio
import json
import logging
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

logger = logging.getLogger("lure-monitor")


# ── State ────────────────────────────────────────────────────────────────────

_scan_lock = asyncio.Lock()
_scan_running = False
_progress_queues: list[asyncio.Queue] = []
_auto_scan_interval: int = config.AUTO_SCAN_INTERVAL_MINUTES  # 0 = disabled
_auto_scan_task: asyncio.Task | None = None
_last_scan_time: datetime | None = None
_next_scan_time: datetime | None = None


# ── Auto-scan scheduler ─────────────────────────────────────────────────────

async def _auto_scan_loop():
    """Background loop that runs scans at the configured interval."""
    global _scan_running, _last_scan_time, _next_scan_time

    while True:
        interval = _auto_scan_interval
        if interval <= 0:
            # Disabled — sleep and check again
            _next_scan_time = None
            await asyncio.sleep(30)
            continue

        _next_scan_time = datetime.now(timezone.utc).__class__.now(timezone.utc)
        from datetime import timedelta
        _next_scan_time = datetime.now(timezone.utc) + timedelta(minutes=interval)

        await asyncio.sleep(interval * 60)

        if _scan_running:
            logger.info("Auto-scan skipped — scan already running")
            continue

        logger.info(f"Auto-scan triggered (interval: {interval}m)")
        _scan_running = True
        try:
            total, new = await run_scan(
                platforms=config.ENABLED_PLATFORMS,
                days_back=config.DAYS_BACK,
            )
            _last_scan_time = datetime.now(timezone.utc)
            logger.info(f"Auto-scan complete: {total} findings ({new} new)")
        except Exception as e:
            logger.error(f"Auto-scan failed: {e}")
        finally:
            _scan_running = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _auto_scan_task
    # Initialize DB on startup
    database = await db.get_db()
    await database.close()
    # Start auto-scan background task
    _auto_scan_task = asyncio.create_task(_auto_scan_loop())
    yield
    # Cleanup
    if _auto_scan_task:
        _auto_scan_task.cancel()


app = FastAPI(title="Claude Code Lure Monitor", lifespan=lifespan)

# Static files and templates
static_dir = Path(__file__).parent / "static"
templates_dir = Path(__file__).parent / "templates"
static_dir.mkdir(exist_ok=True)
templates_dir.mkdir(exist_ok=True)

app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
templates = Jinja2Templates(directory=str(templates_dir))


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.head("/")
async def health_check():
    """HEAD endpoint for Render/Railway health checks."""
    return HTMLResponse("")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    database = await db.get_db()
    try:
        stats = await db.get_stats(database)
        findings = await db.get_findings(database)
        scans = await db.get_scans(database, limit=10)
    finally:
        await database.close()

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "stats": stats,
            "findings": findings,
            "scans": scans,
            "platforms": config.ENABLED_PLATFORMS,
            "scan_running": _scan_running,
            "auto_interval": _auto_scan_interval,
            "next_scan": _next_scan_time.isoformat() if _next_scan_time else None,
        },
    )


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


@app.get("/api/scan/status")
async def scan_status():
    """Poll endpoint — check if scan is running."""
    return JSONResponse({
        "running": _scan_running,
        "auto_interval": _auto_scan_interval,
        "last_scan": _last_scan_time.isoformat() if _last_scan_time else None,
        "next_scan": _next_scan_time.isoformat() if _next_scan_time else None,
    })


@app.get("/api/schedule")
async def get_schedule():
    """Get current auto-scan schedule."""
    return JSONResponse({
        "interval_minutes": _auto_scan_interval,
        "last_scan": _last_scan_time.isoformat() if _last_scan_time else None,
        "next_scan": _next_scan_time.isoformat() if _next_scan_time else None,
        "running": _scan_running,
    })


@app.post("/api/schedule")
async def set_schedule(request: Request):
    """Set auto-scan interval. 0 = disabled."""
    global _auto_scan_interval
    body = await request.json()
    interval = int(body.get("interval_minutes", 0))
    if interval < 0:
        interval = 0
    _auto_scan_interval = interval
    return JSONResponse({
        "interval_minutes": _auto_scan_interval,
        "status": "enabled" if interval > 0 else "disabled",
    })


@app.get("/api/scan/stream")
async def scan_stream():
    """SSE endpoint for live scan progress."""
    queue: asyncio.Queue = asyncio.Queue()
    _progress_queues.append(queue)

    async def event_generator():
        try:
            while True:
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=8)
                    yield f"data: {data}\n\n"
                    parsed = json.loads(data)
                    if parsed.get("status") in ("complete", "error"):
                        break
                except asyncio.TimeoutError:
                    # Send heartbeat every 8s to keep Render proxy alive
                    yield f"data: {json.dumps({'platform': 'heartbeat', 'status': 'waiting', 'found': 0, 'message': ''})}\n\n"
        finally:
            if queue in _progress_queues:
                _progress_queues.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
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
