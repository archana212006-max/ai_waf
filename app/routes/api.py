"""
REST API routes — all JSON endpoints consumed by the dashboard frontend.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Query, HTTPException
from pydantic import BaseModel

from app.models.database import (
    get_stats, get_recent_requests, get_timeline_data,
    get_config, update_config, block_ip, unblock_ip, get_blocked_ips
)
from app.ml.detector import ThreatDetector
from app.models.rule_engine import RuleEngine

logger = logging.getLogger("waf.api")
router = APIRouter()

_detector = ThreatDetector()
_rule_engine = RuleEngine()


@router.get("/stats")
async def api_stats():
    return await get_stats()


@router.get("/timeline")
async def api_timeline(hours: int = Query(6, ge=1, le=48)):
    return await get_timeline_data(hours=hours)


@router.get("/requests")
async def api_requests(
    limit: int = Query(50, ge=1, le=500),
    blocked_only: bool = Query(False)
):
    return await get_recent_requests(limit=limit, blocked_only=blocked_only)


@router.get("/logs")
async def api_logs(
    limit: int = Query(50, ge=1, le=500),
    blocked_only: bool = Query(False)
):
    return await get_recent_requests(limit=limit, blocked_only=blocked_only)


class TestPayloadRequest(BaseModel):
    payload: str
    field:   Optional[str] = "query_string"
    method:  Optional[str] = "GET"


def _build_request_data(payload: str, field: str, method: str) -> dict:
    return {
        "ip": "127.0.0.1", "method": method, "path": "/test",
        "query_string": payload if field == "query_string" else "",
        "body": payload if field == "body" else "",
        "headers": {
            "user-agent": payload if field == "user_agent" else "Mozilla/5.0",
            "host": "localhost", "origin": "", "referer": "",
            "content-type": "application/x-www-form-urlencoded",
        },
        "cookies": {}, "user_agent": "Mozilla/5.0",
        "content_type": "application/x-www-form-urlencoded",
        "referer": "", "origin": "",
        "full_url": f"http://localhost/test?q={payload}",
        "timestamp": "2024-01-01T00:00:00",
    }


@router.post("/test")
async def api_test(body: TestPayloadRequest):
    request_data = _build_request_data(body.payload, body.field or "query_string", body.method or "GET")
    rule_result  = _rule_engine.analyze(request_data)
    ai_result    = _detector.analyze(request_data)
    verdict      = "BLOCKED" if (rule_result["blocked"] or ai_result["blocked"]) else "ALLOWED"
    return {
        "payload": body.payload,
        "verdict": verdict,
        "rule_engine": {
            "blocked": rule_result["blocked"],
            "confidence": rule_result["confidence"],
            "attack_types": rule_result["attack_types"],
            "rule_triggered": rule_result.get("rule_triggered"),
        },
        "ai_engine": {
            "blocked": ai_result["blocked"],
            "confidence": ai_result["confidence"],
            "attack_types": ai_result["attack_types"],
            "details": ai_result.get("details", {}),
        },
    }


@router.post("/test-payload")
async def api_test_payload(body: TestPayloadRequest):
    return await api_test(body)


@router.get("/config")
async def api_get_config():
    return await get_config()


class ConfigUpdateRequest(BaseModel):
    key: str
    value: object


@router.post("/config")
async def api_update_config(body: ConfigUpdateRequest):
    allowed = {"mode", "block_threshold", "rate_limit_enabled", "rate_limit_rps"}
    if body.key not in allowed:
        raise HTTPException(status_code=400, detail=f"Unknown config key: {body.key}")
    await update_config(body.key, body.value)
    return {"status": "ok", "key": body.key, "value": body.value}


@router.get("/blocked-ips")
async def api_blocked_ips():
    return await get_blocked_ips()


class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manual block"
    hours:  Optional[int] = 24


@router.post("/block-ip")
async def api_block_ip(body: BlockIPRequest):
    await block_ip(body.ip, body.reason, body.hours)
    return {"status": "ok", "message": f"IP {body.ip} blocked for {body.hours}h"}


@router.delete("/block-ip/{ip}")
async def api_unblock_ip(ip: str):
    await unblock_ip(ip)
    return {"status": "ok", "message": f"IP {ip} unblocked"}


@router.get("/health")
async def health():
    return {"status": "healthy", "waf": "active", "version": "1.0.0"}
