"""
Rule-Based Detection Engine
Fast, deterministic signature matching (OWASP CRS-style rules).
Complements the AI/ML detector.
"""

import re
import logging
from typing import Dict, List, Any, Tuple, Optional
from app.models.threat import AttackType

logger = logging.getLogger("waf.rule_engine")


# ─────────────────────────────────────────────
# Rule definitions
# ─────────────────────────────────────────────

RULES = [
    # ── SQL Injection ──────────────────────────
    {
        "id": "SQLI-001",
        "name": "Classic OR-based SQLi",
        "attack_type": AttackType.SQLI,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "pattern": r"('|\")\s*(or|and)\s+('|\")?\d+('|\")?\s*=\s*('|\")?\d+",
        "fields": ["query_string", "body"],
    },
    {
        "id": "SQLI-002",
        "name": "UNION SELECT injection",
        "attack_type": AttackType.SQLI,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "pattern": r"union\s+(all\s+)?select\s+",
        "fields": ["query_string", "body", "path"],
    },
    {
        "id": "SQLI-003",
        "name": "SQL comment termination",
        "attack_type": AttackType.SQLI,
        "severity": "HIGH",
        "confidence": 0.80,
        "pattern": r"'[^']*--",
        "fields": ["query_string", "body"],
    },
    {
        "id": "SQLI-004",
        "name": "Stacked queries",
        "attack_type": AttackType.SQLI,
        "severity": "CRITICAL",
        "confidence": 0.92,
        "pattern": r";\s*(select|insert|update|delete|drop|create|alter)\s+",
        "fields": ["query_string", "body"],
    },
    {
        "id": "SQLI-005",
        "name": "Time-based blind SQLi (MySQL)",
        "attack_type": AttackType.SQLI,
        "severity": "CRITICAL",
        "confidence": 0.97,
        "pattern": r"sleep\s*\(\s*\d+\s*\)|benchmark\s*\(",
        "fields": ["query_string", "body"],
    },
    {
        "id": "SQLI-006",
        "name": "Time-based blind SQLi (MSSQL)",
        "attack_type": AttackType.SQLI,
        "severity": "CRITICAL",
        "confidence": 0.97,
        "pattern": r"waitfor\s+delay\s+",
        "fields": ["query_string", "body"],
    },
    {
        "id": "SQLI-007",
        "name": "Information Schema extraction",
        "attack_type": AttackType.SQLI,
        "severity": "CRITICAL",
        "confidence": 0.93,
        "pattern": r"information_schema\.(tables|columns|schemata)",
        "fields": ["query_string", "body"],
    },

    # ── XSS ────────────────────────────────────
    {
        "id": "XSS-001",
        "name": "Script tag injection",
        "attack_type": AttackType.XSS,
        "severity": "CRITICAL",
        "confidence": 0.97,
        "pattern": r"<\s*script[\s>]",
        "fields": ["query_string", "body", "path"],
    },
    {
        "id": "XSS-002",
        "name": "JavaScript protocol handler",
        "attack_type": AttackType.XSS,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "pattern": r"javascript\s*:",
        "fields": ["query_string", "body", "path"],
    },
    {
        "id": "XSS-003",
        "name": "Event handler injection",
        "attack_type": AttackType.XSS,
        "severity": "HIGH",
        "confidence": 0.87,
        "pattern": r"on(load|error|click|mouseover|focus|blur|submit|input|change|keyup|keydown|mouseenter|mouseleave)\s*=",
        "fields": ["query_string", "body"],
    },
    {
        "id": "XSS-004",
        "name": "DOM manipulation",
        "attack_type": AttackType.XSS,
        "severity": "HIGH",
        "confidence": 0.82,
        "pattern": r"document\.(cookie|write|location|getElementById)",
        "fields": ["query_string", "body"],
    },
    {
        "id": "XSS-005",
        "name": "SVG-based XSS",
        "attack_type": AttackType.XSS,
        "severity": "HIGH",
        "confidence": 0.85,
        "pattern": r"<\s*svg[^>]*(onload|onerror)\s*=",
        "fields": ["query_string", "body"],
    },
    {
        "id": "XSS-006",
        "name": "Base64 encoded XSS",
        "attack_type": AttackType.XSS,
        "severity": "MEDIUM",
        "confidence": 0.70,
        "pattern": r"data:text/html;base64,",
        "fields": ["query_string", "body", "path"],
    },

    # ── Path Traversal / LFI ────────────────────
    {
        "id": "LFI-001",
        "name": "Path traversal sequence",
        "attack_type": AttackType.PATH_TRAVERSAL,
        "severity": "HIGH",
        "confidence": 0.88,
        "pattern": r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/",
        "fields": ["path", "query_string"],
    },
    {
        "id": "LFI-002",
        "name": "Sensitive file access attempt",
        "attack_type": AttackType.PATH_TRAVERSAL,
        "severity": "CRITICAL",
        "confidence": 0.95,
        "pattern": r"(/etc/passwd|/etc/shadow|/proc/self|/var/log|boot\.ini|win\.ini)",
        "fields": ["path", "query_string", "body"],
    },
    {
        "id": "LFI-003",
        "name": "PHP wrapper injection",
        "attack_type": AttackType.PATH_TRAVERSAL,
        "severity": "CRITICAL",
        "confidence": 0.93,
        "pattern": r"php://(filter|input|data|expect|zip|phar)",
        "fields": ["query_string", "body"],
    },

    # ── Command Injection ───────────────────────
    {
        "id": "CMDI-001",
        "name": "Shell command injection",
        "attack_type": AttackType.COMMAND_INJECTION,
        "severity": "CRITICAL",
        "confidence": 0.90,
        "pattern": r"[;&|`$]\s*(ls|cat|whoami|id|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\s",
        "fields": ["query_string", "body"],
    },
    {
        "id": "CMDI-002",
        "name": "Null byte injection",
        "attack_type": AttackType.COMMAND_INJECTION,
        "severity": "HIGH",
        "confidence": 0.85,
        "pattern": r"\x00|%00",
        "fields": ["query_string", "body", "path"],
    },

    # ── Scanner / Bot Detection ─────────────────
    {
        "id": "BOT-001",
        "name": "Known attack tool user agent",
        "attack_type": AttackType.SUSPICIOUS,
        "severity": "HIGH",
        "confidence": 0.90,
        "pattern": r"(sqlmap|nikto|nessus|burpsuite|acunetix|nmap|masscan|w3af|dirbuster|wfuzz|nuclei|havij|pangolin)",
        "fields": ["user_agent"],
    },
]


class RuleEngine:
    """Fast signature-based rule matching engine."""

    def __init__(self):
        self.compiled_rules = self._compile_rules()
        logger.info(f"Rule Engine loaded {len(self.compiled_rules)} rules")

    def _compile_rules(self):
        compiled = []
        for rule in RULES:
            try:
                compiled.append({
                    **rule,
                    "compiled_pattern": re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL)
                })
            except re.error as e:
                logger.error(f"Failed to compile rule {rule['id']}: {e}")
        return compiled

    def analyze(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run all rules against the request.
        Returns immediately on CRITICAL match (fail-fast).
        """
        triggered_rules = []
        attack_types = set()
        max_confidence = 0.0

        # Flatten fields
        field_map = {
            "query_string": request_data.get("query_string", ""),
            "body": request_data.get("body", ""),
            "path": request_data.get("path", ""),
            "user_agent": request_data.get("headers", {}).get("user-agent", ""),
            "referer": request_data.get("headers", {}).get("referer", ""),
            "cookie": request_data.get("headers", {}).get("cookie", ""),
        }

        for rule in self.compiled_rules:
            for field in rule["fields"]:
                value = field_map.get(field, "")
                if not value:
                    continue

                if rule["compiled_pattern"].search(value):
                    triggered_rules.append({
                        "id": rule["id"],
                        "name": rule["name"],
                        "field": field,
                        "severity": rule["severity"],
                        "confidence": rule["confidence"],
                    })
                    attack_types.add(rule["attack_type"].value)
                    max_confidence = max(max_confidence, rule["confidence"])

                    # Fail-fast on CRITICAL
                    if rule["severity"] == "CRITICAL":
                        return self._build_result(triggered_rules, attack_types, max_confidence, blocked=True)

        blocked = max_confidence >= 0.80
        return self._build_result(triggered_rules, attack_types, max_confidence, blocked)

    def _build_result(self, triggered, attack_types, confidence, blocked) -> Dict:
        rule_triggered = triggered[0]["id"] if triggered else None
        return {
            "blocked": blocked,
            "confidence": round(confidence, 4),
            "attack_types": list(attack_types),
            "rule_triggered": rule_triggered,
            "details": {"rules_matched": triggered},
        }
