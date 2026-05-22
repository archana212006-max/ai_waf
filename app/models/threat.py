"""
Threat models, enums, and data structures.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


class AttackType(str, Enum):
    SQLI = "SQLi"
    XSS = "XSS"
    CSRF = "CSRF"
    PATH_TRAVERSAL = "Path Traversal"
    COMMAND_INJECTION = "Command Injection"
    SUSPICIOUS = "Suspicious"
    CLEAN = "Clean"


THREAT_COLORS = {
    ThreatLevel.CRITICAL: "#ff2d55",
    ThreatLevel.HIGH: "#ff6b35",
    ThreatLevel.MEDIUM: "#ffd60a",
    ThreatLevel.LOW: "#34c759",
    ThreatLevel.SAFE: "#30d158",
}

ATTACK_TYPE_ICONS = {
    AttackType.SQLI: "🗃️",
    AttackType.XSS: "📜",
    AttackType.CSRF: "🔄",
    AttackType.PATH_TRAVERSAL: "📂",
    AttackType.COMMAND_INJECTION: "💻",
    AttackType.SUSPICIOUS: "🔍",
    AttackType.CLEAN: "✅",
}
