"""
WAF Middleware - Core Protection Engine
Intercepts all HTTP requests and runs AI-powered threat detection
"""

import time
import json
import logging
import asyncio
from typing import Optional, Dict, Any
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from datetime import datetime

from app.ml.detector import ThreatDetector
from app.models.database import get_db_sync, log_request
from app.models.rule_engine import RuleEngine
from app.models.threat import ThreatLevel, AttackType

logger = logging.getLogger("waf.middleware")

# Paths that bypass WAF (dashboard itself)
BYPASS_PATHS = {"/static", "/favicon.ico", "/api/docs", "/api/redoc", "/openapi.json"}


class WAFMiddleware(BaseHTTPMiddleware):
    """
    Main WAF middleware that:
    1. Extracts request features
    2. Runs rule-based detection (fast)
    3. Runs AI/ML-based detection (smart)
    4. Blocks or allows the request
    5. Logs everything to the database
    """

    def __init__(self, app):
        super().__init__(app)
        self.detector = ThreatDetector()
        self.rule_engine = RuleEngine()
        logger.info("WAF Middleware initialized with AI Threat Detector")

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()

        # Bypass WAF for internal dashboard paths
        path = request.url.path
        if any(path.startswith(bp) for bp in BYPASS_PATHS):
            return await call_next(request)

        # Also bypass dashboard and API routes (protect proxy/external targets only)
        if path.startswith("/api/") or path == "/" or path.startswith("/dashboard"):
            return await call_next(request)

        try:
            # Extract request data
            request_data = await self._extract_request_data(request)

            # --- Step 1: Rule-based detection (fast, deterministic) ---
            rule_result = self.rule_engine.analyze(request_data)

            # --- Step 2: AI/ML-based detection ---
            ai_result = self.detector.analyze(request_data)

            # --- Step 3: Combine results ---
            threat_result = self._combine_results(rule_result, ai_result)

            # --- Step 4: Block or allow ---
            process_time = (time.time() - start_time) * 1000

            # Log asynchronously (don't block request)
            asyncio.create_task(
                log_request(
                    ip=request_data["ip"],
                    method=request_data["method"],
                    path=request_data["path"],
                    user_agent=request_data.get("user_agent", ""),
                    is_blocked=threat_result["blocked"],
                    threat_level=threat_result["threat_level"],
                    attack_types=threat_result["attack_types"],
                    confidence=threat_result["confidence"],
                    rule_triggered=threat_result.get("rule_triggered"),
                    process_time_ms=process_time,
                    request_data=request_data
                )
            )

            if threat_result["blocked"]:
                logger.warning(
                    f"🚫 BLOCKED | IP: {request_data['ip']} | "
                    f"Attack: {threat_result['attack_types']} | "
                    f"Confidence: {threat_result['confidence']:.2f} | "
                    f"Path: {path}"
                )
                return self._block_response(threat_result)

            # Allow request
            response = await call_next(request)
            return response

        except Exception as e:
            logger.error(f"WAF middleware error: {e}", exc_info=True)
            return await call_next(request)

    async def _extract_request_data(self, request: Request) -> Dict[str, Any]:
        """Extract all relevant data from the HTTP request."""
        # Get body safely
        body = b""
        try:
            body = await request.body()
        except Exception:
            pass

        body_str = body.decode("utf-8", errors="replace")

        # Get query string
        query_string = str(request.url.query)

        # Get headers (sanitized)
        headers = dict(request.headers)

        # Get cookies
        cookies = dict(request.cookies)

        # Client IP (handle proxies)
        ip = request.client.host if request.client else "unknown"
        forwarded_for = headers.get("x-forwarded-for", "")
        if forwarded_for:
            ip = forwarded_for.split(",")[0].strip()

        return {
            "ip": ip,
            "method": request.method,
            "path": str(request.url.path),
            "query_string": query_string,
            "headers": headers,
            "body": body_str,
            "cookies": cookies,
            "user_agent": headers.get("user-agent", ""),
            "content_type": headers.get("content-type", ""),
            "referer": headers.get("referer", ""),
            "origin": headers.get("origin", ""),
            "full_url": str(request.url),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _combine_results(self, rule_result: Dict, ai_result: Dict) -> Dict:
        """
        Combine rule-based and AI results.
        Block if EITHER engine flags the request with high confidence.
        """
        attack_types = list(set(
            rule_result.get("attack_types", []) +
            ai_result.get("attack_types", [])
        ))

        # Use the higher confidence score
        rule_conf = rule_result.get("confidence", 0.0)
        ai_conf = ai_result.get("confidence", 0.0)
        confidence = max(rule_conf, ai_conf)

        # Determine threat level
        if confidence >= 0.85:
            threat_level = ThreatLevel.CRITICAL
        elif confidence >= 0.65:
            threat_level = ThreatLevel.HIGH
        elif confidence >= 0.40:
            threat_level = ThreatLevel.MEDIUM
        else:
            threat_level = ThreatLevel.LOW

        # Block if either engine says block and confidence is high enough
        blocked = (
            rule_result.get("blocked", False) or
            (ai_result.get("blocked", False) and ai_conf >= 0.60)
        )

        return {
            "blocked": blocked,
            "threat_level": threat_level.value,
            "attack_types": attack_types,
            "confidence": confidence,
            "rule_triggered": rule_result.get("rule_triggered"),
            "rule_details": rule_result.get("details", {}),
            "ai_details": ai_result.get("details", {}),
        }

    def _block_response(self, threat_result: Dict) -> Response:
        """Return a 403 Forbidden response with threat details."""
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden",
                "message": "Request blocked by AI-Powered WAF",
                "threat_level": threat_result["threat_level"],
                "attack_types": threat_result["attack_types"],
                "reference_id": f"WAF-{int(time.time())}",
            },
            headers={
                "X-WAF-Blocked": "true",
                "X-WAF-Threat-Level": threat_result["threat_level"],
                "X-Content-Type-Options": "nosniff",
            }
        )
