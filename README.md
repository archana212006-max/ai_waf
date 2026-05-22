# 🛡️ AI-Powered Web Application Firewall (WAF)

A production-grade, intelligent WAF built with **Python + FastAPI** that uses **AI/ML** to detect and block complex HTTP/HTTPS attacks including SQL Injection (SQLi), Cross-Site Scripting (XSS), CSRF, Path Traversal, and Command Injection — in real time.

---

## 📌 Project Overview

| Feature | Details |
|---|---|
| **Backend** | Python 3.9+, FastAPI, Uvicorn |
| **AI Engine** | Custom multi-model ML threat detector |
| **Rule Engine** | OWASP CRS-style deterministic signatures (19 rules) |
| **Database** | SQLite (async via aiosqlite) |
| **Dashboard** | Dark-themed real-time monitoring UI (HTML/CSS/JS) |
| **Charts** | Chart.js — live traffic timeline + attack breakdown |
| **Proxy** | Transparent reverse proxy (protects any backend) |
| **Tests** | Pytest — 40+ test cases across all attack types |

---

## 🧠 How the AI Detection Works

The WAF uses a **dual-engine architecture**:

### 1. Rule Engine (Fast, Deterministic)
- 19 hand-crafted OWASP-style regex signatures
- Covers SQLi (7 rules), XSS (6), Path Traversal (3), Command Injection (2), Bot Detection (1)
- Fail-fast on CRITICAL threats (immediate block)
- Zero false positives on known attack signatures

### 2. AI/ML Engine (Smart, Adaptive)
Five specialized analyzers each extract features and compute a threat score:

| Analyzer | Method |
|---|---|
| **SQLiAnalyzer** | Keyword tokenization + operator pattern scoring + quote imbalance |
| **XSSAnalyzer** | Tag/attribute/event-handler detection + encoded variant analysis |
| **CSRFAnalyzer** | Origin/Referer mismatch detection + CSRF token presence check |
| **PathTraversalAnalyzer** | Traversal sequence matching + wrapper/protocol detection |
| **GeneralThreatAnalyzer** | Shannon entropy analysis + scanner UA fingerprinting + null-byte detection |

Results from both engines are **combined** — the higher confidence score wins. A request is **blocked** if either engine fires with sufficient confidence.

---

## 🚀 Quick Start

### Option A — Automated Setup (Recommended)
```bash
git clone <repo>
cd ai_waf
python setup.py
```

### Option B — Manual Setup
```bash
# 1. Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env: set WAF_TARGET to your backend URL

# 4. Run the WAF
python main.py
```

Open the dashboard at **http://localhost:8000**

---

## 📁 Project Structure

```
ai_waf/
├── main.py                        # Application entry point
├── requirements.txt               # Python dependencies
├── setup.py                       # One-click setup script
├── .env.example                   # Environment config template
│
├── app/
│   ├── middleware/
│   │   └── waf_middleware.py      # Core WAF interception layer
│   │
│   ├── ml/
│   │   └── detector.py            # AI/ML multi-model threat detector
│   │
│   ├── models/
│   │   ├── database.py            # Async SQLite database layer
│   │   ├── rule_engine.py         # Signature-based rule engine (19 rules)
│   │   └── threat.py              # Threat enums and data models
│   │
│   └── routes/
│       ├── api.py                 # REST API (stats, logs, config, IP mgmt)
│       ├── dashboard.py           # Dashboard page routes
│       └── proxy.py               # Reverse proxy to backend
│
├── static/
│   ├── css/style.css              # Dashboard styles (dark cybersecurity theme)
│   └── js/
│       ├── dashboard.js           # Live stats, charts, attack table
│       ├── logs.js                # Traffic logs with detail panel
│       └── config.js              # Config, IP management, rule viewer
│
├── templates/
│   ├── dashboard.html             # Real-time monitoring dashboard
│   ├── logs.html                  # Full traffic log viewer
│   └── config.html                # WAF configuration page
│
├── tests/
│   └── test_waf.py                # 40+ pytest test cases
│
└── logs/
    ├── waf.log                    # Application log (auto-created)
    └── waf.db                     # SQLite database (auto-created)
```

---

## 🖥️ Dashboard Pages

### 📊 Dashboard (`/`)
- **Live stat cards**: Total requests, blocked attacks, block rate, requests/min
- **Traffic timeline**: Chart.js line chart (6h/12h/24h range selector) — auto-refreshes every 5s
- **Attack type donut chart**: Breakdown of SQLi, XSS, CSRF, etc.
- **Recent blocked requests table**: IP, method, path, attack type, confidence, threat level
- **Top attacker IPs**: With bar visualization
- **Payload Tester modal**: Test any payload against both engines instantly

### 📋 Traffic Logs (`/logs`)
- Full request history (allowed + blocked)
- Filter: blocked-only, row count (50/100/200/500)
- Click any row → detail panel (IP, path, body, UA, confidence, rule triggered)
- **Block IP** button directly from log rows

### ⚙️ Configuration (`/config`)
- WAF mode: Active / Monitor / Disabled
- AI confidence threshold slider
- Rate limiting toggle + RPS setting
- IP blocklist: Add/remove IPs manually
- Active rules viewer: All 19 rules with severity and type badges

---

## 🔌 REST API

| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Aggregate stats (total, blocked, breakdown) |
| `/api/timeline?hours=6` | GET | Traffic timeline for charts |
| `/api/requests?limit=50&blocked_only=false` | GET | Request logs |
| `/api/test` | POST | Test a payload without blocking |
| `/api/config` | GET/POST | Read/update WAF config |
| `/api/blocked-ips` | GET | List blocked IPs |
| `/api/block-ip` | POST | Block an IP |
| `/api/block-ip/{ip}` | DELETE | Unblock an IP |
| `/api/health` | GET | Health check |
| `/api/docs` | GET | Interactive Swagger docs |

---

## 🧪 Running Tests

```bash
# Activate venv first
source venv/bin/activate

# Run all tests
pytest tests/ -v

# Run specific test class
pytest tests/test_waf.py::TestSQLiDetection -v
pytest tests/test_waf.py::TestXSSDetection -v
pytest tests/test_waf.py::TestCSRFDetection -v
pytest tests/test_waf.py::TestPathTraversalDetection -v
pytest tests/test_waf.py::TestCommandInjectionDetection -v
pytest tests/test_waf.py::TestCleanRequests -v
```

**Test coverage:**
- SQLi: 13 payloads (UNION, time-based, stacked, comment-based)
- XSS: 13 payloads (script tags, event handlers, protocol handlers, SVG, base64)
- CSRF: Origin/Referer mismatch, missing token
- Path Traversal: 10 payloads (../  encoded, PHP wrappers, sensitive files)
- Command Injection: 8 payloads (shell metacharacters, pipes, backticks)
- Scanner bots: 9 known attack tool UAs
- Clean requests: 9 payloads (false-positive prevention)
- Edge cases: empty, unicode, very long, double-encoded payloads

---

## 🔧 Configuration

Edit `.env` to configure the WAF:

```env
WAF_TARGET=http://localhost:9000    # Backend server to protect
WAF_HOST=0.0.0.0
WAF_PORT=8000
WAF_MODE=active                     # active | monitor | disabled
BLOCK_THRESHOLD=0.60                # AI confidence threshold (0.0-1.0)
RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPS=100
```

---

## 🛡️ Attacks Detected

| Attack Type | Detection Method | Rules |
|---|---|---|
| SQL Injection (SQLi) | Rule signatures + AI keyword/operator scoring | 7 rules |
| Cross-Site Scripting (XSS) | Rule signatures + AI tag/event analysis | 6 rules |
| CSRF | AI origin/referer mismatch + token detection | AI only |
| Path Traversal / LFI | Rule signatures + AI pattern matching | 3 rules |
| Command Injection | Rule signatures + AI heuristics | 2 rules |
| Scanner/Bot detection | UA fingerprinting + entropy analysis | 1 rule |

---

## ⚙️ How It Works as a Reverse Proxy

```
Client Request
     │
     ▼
┌─────────────────────────────────┐
│       WAF (port 8000)           │
│                                 │
│  1. Extract request features    │
│  2. Rule Engine scan (fast)     │
│  3. AI/ML analysis (smart)      │
│  4. Combine + decide            │
│     │                           │
│     ├─ BLOCKED → 403 response   │
│     └─ ALLOWED → forward        │
└─────────────────────────────────┘
     │
     ▼
Backend Server (WAF_TARGET)
```

Set `WAF_TARGET` to any HTTP server you want to protect. All traffic goes through the WAF at port 8000.

---

## 📋 Requirements

- Python 3.9+
- pip
- No external services needed (SQLite built-in)

---

## 👨‍💻 Author

**AI-Powered Web Application Firewall**  
Built with FastAPI + Custom ML Detection Engine

---

## 📄 License

MIT License — free to use, modify, and distribute.
#   a i _ w a f  
 #   a i _ w a f  
 