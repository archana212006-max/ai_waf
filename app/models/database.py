"""
Database layer using SQLite (via aiosqlite).
Stores all WAF request logs, blocked events, and stats.
"""

import asyncio
import aiosqlite
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("waf.database")

DB_PATH = Path("logs/waf.db")

# Global connection pool
_db_connection: Optional[aiosqlite.Connection] = None
_lock = asyncio.Lock()


async def get_db() -> aiosqlite.Connection:
    global _db_connection
    if _db_connection is None:
        _db_connection = await aiosqlite.connect(str(DB_PATH))
        _db_connection.row_factory = aiosqlite.Row
    return _db_connection


def get_db_sync():
    """Placeholder for sync access (not used in async context)."""
    return None


async def init_db():
    """Create tables if they don't exist."""
    DB_PATH.parent.mkdir(exist_ok=True)
    db = await get_db()

    await db.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            user_agent TEXT,
            is_blocked INTEGER DEFAULT 0,
            threat_level TEXT,
            attack_types TEXT,
            confidence REAL DEFAULT 0.0,
            rule_triggered TEXT,
            process_time_ms REAL,
            request_body TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)

    await db.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            reason TEXT,
            blocked_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT,
            is_active INTEGER DEFAULT 1
        )
    """)

    await db.execute("""
        CREATE TABLE IF NOT EXISTS waf_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT DEFAULT (datetime('now'))
        )
    """)

    # Default config
    await db.execute("""
        INSERT OR IGNORE INTO waf_config (key, value) VALUES
            ('mode', '"active"'),
            ('block_threshold', '0.60'),
            ('rate_limit_enabled', 'true'),
            ('rate_limit_rps', '100'),
            ('whitelist_ips', '[]'),
            ('blacklist_ips', '[]')
    """)

    # Indexes
    await db.execute("CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)")
    await db.execute("CREATE INDEX IF NOT EXISTS idx_requests_blocked ON requests(is_blocked)")

    await db.commit()
    logger.info("Database initialized")


async def log_request(
    ip: str,
    method: str,
    path: str,
    user_agent: str,
    is_blocked: bool,
    threat_level: str,
    attack_types: List[str],
    confidence: float,
    rule_triggered: Optional[str],
    process_time_ms: float,
    request_data: Dict
):
    """Insert a request log entry."""
    try:
        db = await get_db()
        await db.execute("""
            INSERT INTO requests
                (timestamp, ip, method, path, user_agent, is_blocked, threat_level,
                 attack_types, confidence, rule_triggered, process_time_ms, request_body)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.utcnow().isoformat(),
            ip,
            method,
            path[:500],
            user_agent[:300],
            1 if is_blocked else 0,
            threat_level,
            json.dumps(attack_types),
            round(confidence, 4),
            rule_triggered,
            round(process_time_ms, 2),
            request_data.get("body", "")[:1000],
        ))
        await db.commit()
    except Exception as e:
        logger.error(f"Failed to log request: {e}")


async def get_stats() -> Dict[str, Any]:
    """Get aggregate statistics for the dashboard."""
    db = await get_db()

    # Total requests
    async with db.execute("SELECT COUNT(*) FROM requests") as cur:
        total = (await cur.fetchone())[0]

    # Blocked requests
    async with db.execute("SELECT COUNT(*) FROM requests WHERE is_blocked=1") as cur:
        blocked = (await cur.fetchone())[0]

    # Last 24h
    since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    async with db.execute("SELECT COUNT(*) FROM requests WHERE timestamp > ?", (since,)) as cur:
        last_24h = (await cur.fetchone())[0]

    # Last 24h blocked
    async with db.execute(
        "SELECT COUNT(*) FROM requests WHERE is_blocked=1 AND timestamp > ?", (since,)
    ) as cur:
        blocked_24h = (await cur.fetchone())[0]

    # Attack type breakdown
    async with db.execute(
        "SELECT attack_types, COUNT(*) as cnt FROM requests WHERE is_blocked=1 GROUP BY attack_types"
    ) as cur:
        rows = await cur.fetchall()

    attack_breakdown = {}
    for row in rows:
        types = json.loads(row[0] or "[]")
        for t in types:
            attack_breakdown[t] = attack_breakdown.get(t, 0) + int(row[1])

    # Top attacker IPs
    async with db.execute("""
        SELECT ip, COUNT(*) as cnt
        FROM requests WHERE is_blocked=1
        GROUP BY ip ORDER BY cnt DESC LIMIT 5
    """) as cur:
        top_ips = [{"ip": r[0], "count": r[1]} for r in await cur.fetchall()]

    # Avg confidence
    async with db.execute(
        "SELECT AVG(confidence) FROM requests WHERE is_blocked=1"
    ) as cur:
        avg_conf = (await cur.fetchone())[0] or 0.0

    # Requests per minute (last hour)
    since_1h = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    async with db.execute(
        "SELECT COUNT(*) FROM requests WHERE timestamp > ?", (since_1h,)
    ) as cur:
        last_1h = (await cur.fetchone())[0]
    rpm = round(last_1h / 60, 2)

    return {
        "total_requests": total,
        "total_blocked": blocked,
        "requests_24h": last_24h,
        "blocked_24h": blocked_24h,
        "block_rate": round((blocked / total * 100) if total > 0 else 0, 1),
        "attack_breakdown": attack_breakdown,
        "top_attacker_ips": top_ips,
        "avg_confidence": round(avg_conf * 100, 1),
        "requests_per_minute": rpm,
    }


async def get_recent_requests(limit: int = 50, blocked_only: bool = False) -> List[Dict]:
    """Fetch recent request logs."""
    db = await get_db()
    where = "WHERE is_blocked=1" if blocked_only else ""
    async with db.execute(
        f"SELECT * FROM requests {where} ORDER BY id DESC LIMIT ?", (limit,)
    ) as cur:
        rows = await cur.fetchall()
    result = []
    for row in rows:
        d = dict(row)
        d["attack_types"] = json.loads(d.get("attack_types") or "[]")
        result.append(d)
    return result


async def get_timeline_data(hours: int = 6) -> List[Dict]:
    """Get request/block counts per 10-minute bucket for charting."""
    db = await get_db()
    since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

    async with db.execute("""
        SELECT
            strftime('%Y-%m-%dT%H:', timestamp) ||
            CASE
                WHEN CAST(strftime('%M', timestamp) AS INTEGER) < 10 THEN '00'
                WHEN CAST(strftime('%M', timestamp) AS INTEGER) < 20 THEN '10'
                WHEN CAST(strftime('%M', timestamp) AS INTEGER) < 30 THEN '20'
                WHEN CAST(strftime('%M', timestamp) AS INTEGER) < 40 THEN '30'
                WHEN CAST(strftime('%M', timestamp) AS INTEGER) < 50 THEN '40'
                ELSE '50'
            END || ':00' AS bucket,
            COUNT(*) as total,
            SUM(is_blocked) as blocked
        FROM requests
        WHERE timestamp > ?
        GROUP BY bucket
        ORDER BY bucket
    """, (since,)) as cur:
        rows = await cur.fetchall()

    return [{"bucket": r[0], "total": r[1], "blocked": r[2]} for r in rows]


async def get_config() -> Dict[str, Any]:
    db = await get_db()
    async with db.execute("SELECT key, value FROM waf_config") as cur:
        rows = await cur.fetchall()
    return {r[0]: json.loads(r[1]) for r in rows}


async def update_config(key: str, value: Any):
    db = await get_db()
    await db.execute(
        "INSERT OR REPLACE INTO waf_config (key, value, updated_at) VALUES (?, ?, datetime('now'))",
        (key, json.dumps(value))
    )
    await db.commit()


async def block_ip(ip: str, reason: str = "Manual block", hours: int = 24):
    db = await get_db()
    expires = (datetime.utcnow() + timedelta(hours=hours)).isoformat()
    await db.execute("""
        INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at, expires_at, is_active)
        VALUES (?, ?, datetime('now'), ?, 1)
    """, (ip, reason, expires))
    await db.commit()


async def unblock_ip(ip: str):
    db = await get_db()
    await db.execute("UPDATE blocked_ips SET is_active=0 WHERE ip=?", (ip,))
    await db.commit()


async def get_blocked_ips() -> List[Dict]:
    db = await get_db()
    async with db.execute(
        "SELECT * FROM blocked_ips WHERE is_active=1 ORDER BY blocked_at DESC"
    ) as cur:
        rows = await cur.fetchall()
    return [dict(r) for r in rows]
