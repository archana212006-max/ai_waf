"""
AI-Powered Web Application Firewall (WAF)
Main application entry point — run with: python main.py
"""

import uvicorn
import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from app.middleware.waf_middleware import WAFMiddleware
from app.routes import dashboard, api, proxy
from app.models.database import init_db

# ── Auto-create required folders ──────────────────────────
Path("logs").mkdir(exist_ok=True)
Path("static/css").mkdir(parents=True, exist_ok=True)
Path("static/js").mkdir(parents=True, exist_ok=True)
Path("templates").mkdir(exist_ok=True)

# ── Logging ───────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/waf.log"),
    ],
)
logger = logging.getLogger("waf.main")

# ── FastAPI app ────────────────────────────────────────────
app = FastAPI(
    title="AI-Powered Web Application Firewall",
    description="Real-time HTTP traffic monitoring and AI threat blocking",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS (allow dashboard to call the API)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WAF Middleware — inspects every request
app.add_middleware(WAFMiddleware)

# Static files and HTML templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Routers
app.include_router(dashboard.router,            tags=["Dashboard"])
app.include_router(api.router,     prefix="/api", tags=["API"])
app.include_router(proxy.router,   prefix="/proxy", tags=["Proxy"])


@app.on_event("startup")
async def startup():
    logger.info("Starting AI-Powered WAF...")
    await init_db()
    logger.info("WAF is ACTIVE — dashboard at http://localhost:8000")


@app.on_event("shutdown")
async def shutdown():
    logger.info("WAF shutting down.")


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    print("\n" + "="*50)
    print("   Shield  AI-Powered Web Application Firewall")
    print("="*50)
    print(f"   Dashboard  ->  http://localhost:{port}")
    print(f"   API Docs   ->  http://localhost:{port}/api/docs")
    print("   Press Ctrl+C to stop")
    print("="*50 + "\n")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False, log_level="info")