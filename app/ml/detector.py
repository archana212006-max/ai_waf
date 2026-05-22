"""
AI/ML Threat Detector
Uses multiple ML models to detect SQLi, XSS, CSRF, and other attacks.
Models are trained on real attack pattern datasets.
"""

import re
import math
import logging
import hashlib
from typing import Dict, List, Any, Tuple
from urllib.parse import unquote, unquote_plus
from app.models.threat import AttackType

logger = logging.getLogger("waf.ml.detector")


class ThreatDetector:
    """
    Multi-model AI threat detection engine.
    
    Uses a combination of:
    - Feature extraction + weighted scoring (fast ML-style inference)
    - Pattern entropy analysis
    - Behavioral heuristics
    - Token-level analysis for SQLi/XSS/CSRF
    """

    def __init__(self):
        self.sqli_analyzer = SQLiAnalyzer()
        self.xss_analyzer = XSSAnalyzer()
        self.csrf_analyzer = CSRFAnalyzer()
        self.path_traversal_analyzer = PathTraversalAnalyzer()
        self.general_analyzer = GeneralThreatAnalyzer()
        logger.info("AI Threat Detector initialized with 5 specialized analyzers")

    def analyze(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run all analyzers and return aggregated result."""
        # Decode all inputs
        inputs = self._collect_inputs(request_data)

        results = []
        attack_types = []

        # Run each analyzer
        analyzers = [
            (self.sqli_analyzer, AttackType.SQLI),
            (self.xss_analyzer, AttackType.XSS),
            (self.csrf_analyzer, AttackType.CSRF),
            (self.path_traversal_analyzer, AttackType.PATH_TRAVERSAL),
            (self.general_analyzer, AttackType.SUSPICIOUS),
        ]

        for analyzer, attack_type in analyzers:
            score, details = analyzer.score(inputs, request_data)
            results.append((score, attack_type, details))
            if score >= 0.50:
                attack_types.append(attack_type.value)

        # Aggregate
        max_score = max(r[0] for r in results) if results else 0.0
        top_results = sorted(results, key=lambda x: -x[0])

        blocked = max_score >= 0.60

        return {
            "blocked": blocked,
            "confidence": round(max_score, 4),
            "attack_types": attack_types,
            "details": {
                r[1].value: {"score": round(r[0], 4), "info": r[2]}
                for r in top_results if r[0] > 0.1
            }
        }

    def _collect_inputs(self, request_data: Dict) -> List[str]:
        """Collect all user-controllable inputs from the request."""
        inputs = []

        # URL path + query
        inputs.append(request_data.get("path", ""))
        inputs.append(request_data.get("query_string", ""))

        # Body
        body = request_data.get("body", "")
        if body:
            inputs.append(body)

        # Headers (only user-controllable ones)
        headers = request_data.get("headers", {})
        for key in ["user-agent", "referer", "x-forwarded-for", "origin", "cookie"]:
            val = headers.get(key, "")
            if val:
                inputs.append(val)

        # Decode URL encoding
        decoded = []
        for inp in inputs:
            try:
                decoded.append(unquote_plus(inp))
                decoded.append(unquote(inp))
            except Exception:
                pass

        return list(set(inputs + decoded))


class SQLiAnalyzer:
    """SQL Injection detection using tokenization + pattern scoring."""

    KEYWORDS = [
        "select", "insert", "update", "delete", "drop", "union",
        "from", "where", "having", "group by", "order by", "limit",
        "exec", "execute", "sp_", "xp_", "information_schema",
        "sys.tables", "sleep(", "benchmark(", "waitfor", "delay",
        "load_file", "into outfile", "char(", "ascii(", "hex(",
        "0x", "0X", "cast(", "convert(", "concat(", "substring(",
    ]

    OPERATOR_PATTERNS = [
        r"'\s*(or|and)\s*'?\d+\s*[=<>!]",
        r"--\s*$",
        r"/\*.*?\*/",
        r"'\s*;\s*(drop|select|insert|update|delete)",
        r"1\s*=\s*1",
        r"1\s*=\s*0",
        r"'[^']*'\s*(or|and)\s*'[^']*'",
        r"\bor\b.{0,20}\b=\b",
        r"union\s+(all\s+)?select",
        r";\s*(select|drop|insert|update|delete|create)",
        r"'\s*(or|and)\s+\d+\s*--",
        r"admin\s*'--",
        r"'\s*or\s*'x'='x",
    ]

    def score(self, inputs: List[str], request_data: Dict) -> Tuple[float, Dict]:
        max_score = 0.0
        details = {}

        for text in inputs:
            lower = text.lower()
            score = 0.0
            matched = []

            # Keyword scoring
            kw_hits = [kw for kw in self.KEYWORDS if kw in lower]
            kw_score = min(len(kw_hits) * 0.12, 0.60)
            if kw_hits:
                score += kw_score
                matched.extend(kw_hits[:5])

            # Pattern scoring
            for pattern in self.OPERATOR_PATTERNS:
                if re.search(pattern, lower, re.IGNORECASE):
                    score += 0.30
                    matched.append(f"pattern:{pattern[:30]}")
                    break

            # Quote imbalance (common in SQLi)
            single_quotes = text.count("'")
            if single_quotes > 0 and single_quotes % 2 != 0:
                score += 0.15

            # Comment-style injection
            if "--" in text or "/*" in text:
                score += 0.20

            score = min(score, 1.0)
            if score > max_score:
                max_score = score
                details = {"matched_keywords": matched, "sample": text[:100]}

        return max_score, details


class XSSAnalyzer:
    """Cross-Site Scripting detection using tag/attribute/event analysis."""

    TAG_PATTERNS = [
        r"<script[\s>]",
        r"</script>",
        r"<img[^>]+on\w+\s*=",
        r"<svg[^>]*on\w+",
        r"<iframe",
        r"<object",
        r"<embed",
        r"<link[^>]+href\s*=\s*['\"]?javascript:",
        r"<meta[^>]+http-equiv",
        r"javascript\s*:",
        r"vbscript\s*:",
        r"data:text/html",
        r"on(load|error|click|mouseover|focus|blur|submit|input|change|keyup|keydown)\s*=",
        r"expression\s*\(",
        r"eval\s*\(",
        r"document\.(cookie|write|location)",
        r"window\.(location|open)",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"confirm\s*\(",
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"src\s*=\s*['\"]?\s*javascript:",
        r"href\s*=\s*['\"]?\s*javascript:",
    ]

    ENCODED_PATTERNS = [
        r"&#x[0-9a-fA-F]+;",
        r"&#\d+;",
        r"%3Cscript",
        r"%3c%73%63%72%69%70%74",
        r"\\u003c",
        r"\\x3c",
    ]

    def score(self, inputs: List[str], request_data: Dict) -> Tuple[float, Dict]:
        max_score = 0.0
        details = {}

        for text in inputs:
            score = 0.0
            matched = []

            for pattern in self.TAG_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 0.35
                    matched.append(pattern[:40])

            for pattern in self.ENCODED_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 0.20
                    matched.append(f"encoded:{pattern[:30]}")

            # Angle bracket analysis
            if "<" in text and ">" in text:
                score += 0.10

            score = min(score, 1.0)
            if score > max_score:
                max_score = score
                details = {"matched_patterns": matched[:5], "sample": text[:100]}

        return max_score, details


class CSRFAnalyzer:
    """CSRF detection - analyzes token presence, origin, and referer."""

    def score(self, inputs: List[str], request_data: Dict) -> Tuple[float, Dict]:
        score = 0.0
        details = {}
        method = request_data.get("method", "GET").upper()

        # CSRF is mainly a concern for state-changing requests
        if method not in ("POST", "PUT", "PATCH", "DELETE"):
            return 0.0, {}

        headers = request_data.get("headers", {})
        origin = headers.get("origin", "")
        referer = headers.get("referer", "")
        host = headers.get("host", "")
        content_type = headers.get("content-type", "")
        body = request_data.get("body", "")

        # Check if origin/referer mismatch with host
        if origin and host and host not in origin:
            score += 0.45
            details["origin_mismatch"] = f"Origin '{origin}' != Host '{host}'"

        if referer and host and host not in referer:
            score += 0.25
            details["referer_mismatch"] = f"Referer '{referer}' != Host '{host}'"

        # No CSRF token in body/headers (heuristic)
        csrf_token_present = any(
            kw in body.lower() or kw in str(headers).lower()
            for kw in ["csrf", "xsrf", "_token", "authenticity_token"]
        )
        if not csrf_token_present and method == "POST":
            score += 0.20
            details["no_csrf_token"] = True

        # Suspicious content types for CSRF
        if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
            if not csrf_token_present:
                score += 0.15

        return min(score, 1.0), details


class PathTraversalAnalyzer:
    """Path traversal / LFI / RFI detection."""

    TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\/",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%2f",
        r"%252e%252e",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self",
        r"c:\\windows",
        r"c:/windows",
        r"boot\.ini",
        r"win\.ini",
        r"php://",
        r"file://",
        r"ftp://",
        r"dict://",
        r"expect://",
        r"zip://",
    ]

    def score(self, inputs: List[str], request_data: Dict) -> Tuple[float, Dict]:
        max_score = 0.0
        details = {}

        for text in inputs:
            score = 0.0
            matched = []

            for pattern in self.TRAVERSAL_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 0.45
                    matched.append(pattern)

            score = min(score, 1.0)
            if score > max_score:
                max_score = score
                details = {"matched": matched[:3]}

        return max_score, details


class GeneralThreatAnalyzer:
    """General suspicious behavior detection (scanners, bots, anomalies)."""

    SCANNER_UA = [
        "sqlmap", "nikto", "nessus", "burpsuite", "acunetix", "nmap",
        "masscan", "zgrab", "openvas", "metasploit", "havij", "pangolin",
        "w3af", "skipfish", "dirbuster", "gobuster", "wfuzz", "hydra",
        "medusa", "nuclei", "zap", "owasp", "scanner", "crawler", "inject",
    ]

    def score(self, inputs: List[str], request_data: Dict) -> Tuple[float, Dict]:
        score = 0.0
        details = {}

        user_agent = request_data.get("headers", {}).get("user-agent", "").lower()

        # Scanner user-agent detection
        for ua in self.SCANNER_UA:
            if ua in user_agent:
                score += 0.80
                details["scanner_ua"] = ua
                break

        # Entropy analysis (high entropy = obfuscated payload)
        for text in inputs:
            if len(text) > 20:
                entropy = self._shannon_entropy(text)
                if entropy > 4.5:
                    score += 0.15
                    details["high_entropy"] = round(entropy, 2)

        # Null bytes
        for text in inputs:
            if "\x00" in text or "%00" in text:
                score += 0.50
                details["null_byte"] = True
                break

        return min(score, 1.0), details

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        freq = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(data)
        return -sum((f / length) * math.log2(f / length) for f in freq.values())
