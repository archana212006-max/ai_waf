"""
Reverse Proxy Route
The WAF can act as a reverse proxy — all traffic sent to /proxy/* is
inspected by the WAF middleware then forwarded to the configured upstream.
"""

import logging
import httpx
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger("waf.proxy")
router = APIRouter()

UPSTREAM_URL = "http://localhost:9000"  # Change to your backend


@router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def reverse_proxy(request: Request, path: str):
    target_url = f"{UPSTREAM_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    headers = dict(request.headers)
    headers.pop("host", None)
    headers["X-Forwarded-By"] = "AI-WAF/1.0"
    headers["X-Real-IP"] = request.client.host if request.client else "unknown"

    try:
        body = await request.body()
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=True,
            )
            return Response(
                content=upstream_resp.content,
                status_code=upstream_resp.status_code,
                headers=dict(upstream_resp.headers),
                media_type=upstream_resp.headers.get("content-type"),
            )
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={
                "error": "Bad Gateway",
                "message": "WAF could not connect to upstream. Configure UPSTREAM_URL in app/routes/proxy.py",
                "upstream": UPSTREAM_URL,
            }
        )
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return JSONResponse(status_code=502, content={"error": str(e)})
