"""
Detection Engine — Rule Definitions
Day 2: Rule-Based Attack Detection

All patterns use compiled regex for zero per-request compilation overhead.
Each rule maps to an attack category with a confidence score (0.0 – 1.0).

Rule structure:
    {
        "pattern": compiled re.Pattern,
        "attack_type": str,
        "confidence": float,
    }

Evaluated against: endpoint (URL path + query string), payload (body), headers.
"""

import re
from typing import TypedDict


class Rule(TypedDict):
    pattern: "re.Pattern[str]"
    attack_type: str
    confidence: float


# ---------------------------------------------------------------------------
# Helper: compile with IGNORECASE | DOTALL once at import time
# ---------------------------------------------------------------------------
def _c(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# ===========================================================================
# 1. SQL INJECTION
# ===========================================================================
SQL_INJECTION_RULES: list[Rule] = [
    {"pattern": _c(r"(\bSELECT\b.+\bFROM\b|\bUNION\b.+\bSELECT\b)"),          "attack_type": "SQL Injection", "confidence": 0.95},
    {"pattern": _c(r"\bUNION\s+(ALL\s+)?SELECT\b"),                              "attack_type": "SQL Injection", "confidence": 0.97},
    {"pattern": _c(r"'\s*OR\s+'?1'?\s*=\s*'?1'?"),                              "attack_type": "SQL Injection", "confidence": 0.98},
    {"pattern": _c(r"'\s*OR\s+1\s*=\s*1"),                                       "attack_type": "SQL Injection", "confidence": 0.98},
    {"pattern": _c(r"'\s*OR\s+'a'\s*=\s*'a'"),                                   "attack_type": "SQL Injection", "confidence": 0.97},
    {"pattern": _c(r";\s*--"),                                                    "attack_type": "SQL Injection", "confidence": 0.90},
    {"pattern": _c(r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b"),     "attack_type": "SQL Injection", "confidence": 0.85},
    {"pattern": _c(r"\bDROP\s+TABLE\b"),                                          "attack_type": "SQL Injection", "confidence": 0.99},
    {"pattern": _c(r"\binformation_schema\b"),                                    "attack_type": "SQL Injection", "confidence": 0.93},
    {"pattern": _c(r"(\'|\"|`)\s*(--|\#)"),                                       "attack_type": "SQL Injection", "confidence": 0.88},
    {"pattern": _c(r"\bEXEC(\s|\()+\b"),                                          "attack_type": "SQL Injection", "confidence": 0.90},
    {"pattern": _c(r"\bSLEEP\s*\(\s*\d+\s*\)"),                                  "attack_type": "SQL Injection", "confidence": 0.95},  # Time-based blind
    {"pattern": _c(r"\bWAITFOR\s+DELAY\b"),                                      "attack_type": "SQL Injection", "confidence": 0.95},
    {"pattern": _c(r"\bBENCHMARK\s*\("),                                          "attack_type": "SQL Injection", "confidence": 0.93},
]

# ===========================================================================
# 2. CROSS-SITE SCRIPTING (XSS)
# ===========================================================================
XSS_RULES: list[Rule] = [
    {"pattern": _c(r"javascript\s*:"),                                            "attack_type": "XSS", "confidence": 0.95},
    {"pattern": _c(r"\bon\w+\s*=\s*[\"']?\s*(javascript:|alert|confirm|prompt)"), "attack_type": "XSS", "confidence": 0.97},
    {"pattern": _c(r"\bonerror\s*="),                                             "attack_type": "XSS", "confidence": 0.95},
    {"pattern": _c(r"\bonload\s*="),                                              "attack_type": "XSS", "confidence": 0.95},
    {"pattern": _c(r"alert\s*\("),                                                "attack_type": "XSS", "confidence": 0.90},
    {"pattern": _c(r"document\s*\.\s*cookie"),                                    "attack_type": "XSS", "confidence": 0.97},
    {"pattern": _c(r"<\s*script[\s>]"),                                           "attack_type": "XSS", "confidence": 0.98},
    {"pattern": _c(r"<\s*img\s[^>]*\bon\w+\s*="),                                "attack_type": "XSS", "confidence": 0.95},
    {"pattern": _c(r"<\s*svg\s[^>]*\bon\w+\s*="),                                "attack_type": "XSS", "confidence": 0.95},
    {"pattern": _c(r"<\s*iframe[\s>]"),                                           "attack_type": "XSS", "confidence": 0.90},
    {"pattern": _c(r"eval\s*\("),                                                 "attack_type": "XSS", "confidence": 0.85},
    {"pattern": _c(r"expression\s*\("),                                           "attack_type": "XSS", "confidence": 0.88},
    {"pattern": _c(r"&#x?[0-9a-f]+;"),                                           "attack_type": "XSS", "confidence": 0.75},  # HTML entity encoding evasion
]

# ===========================================================================
# 3. COMMAND INJECTION
# ===========================================================================
COMMAND_INJECTION_RULES: list[Rule] = [
    {"pattern": _c(r";\s*(ls|cat|pwd|id|uname|whoami|ifconfig|netstat|ps)\b"),   "attack_type": "Command Injection", "confidence": 0.95},
    {"pattern": _c(r"&&\s*(ls|cat|pwd|id|uname|whoami)"),                        "attack_type": "Command Injection", "confidence": 0.95},
    {"pattern": _c(r"\|\s*(bash|sh|zsh|ksh|csh)\b"),                             "attack_type": "Command Injection", "confidence": 0.97},
    {"pattern": _c(r"\$\s*\("),                                                   "attack_type": "Command Injection", "confidence": 0.90},  # $(command)
    {"pattern": _c(r"`[^`]+`"),                                                   "attack_type": "Command Injection", "confidence": 0.88},  # backtick exec
    {"pattern": _c(r"\bwhoami\b"),                                                "attack_type": "Command Injection", "confidence": 0.92},
    {"pattern": _c(r"\bcurl\s+https?://"),                                        "attack_type": "Command Injection", "confidence": 0.88},
    {"pattern": _c(r"\bwget\s+https?://"),                                        "attack_type": "Command Injection", "confidence": 0.88},
    {"pattern": _c(r"\bnc\s+-\w*\s+\d+"),                                         "attack_type": "Command Injection", "confidence": 0.93},  # netcat reverse shell
    {"pattern": _c(r"/dev/tcp/"),                                                  "attack_type": "Command Injection", "confidence": 0.97},  # bash tcp redirect
    {"pattern": _c(r"\bchmod\s+[0-7]{3,4}\b"),                                    "attack_type": "Command Injection", "confidence": 0.90},
    {"pattern": _c(r";\s*python\s+-c\b"),                                          "attack_type": "Command Injection", "confidence": 0.95},
]

# ===========================================================================
# 4. PATH TRAVERSAL
# ===========================================================================
PATH_TRAVERSAL_RULES: list[Rule] = [
    {"pattern": _c(r"(\.\./){2,}"),                                               "attack_type": "Path Traversal", "confidence": 0.95},
    {"pattern": _c(r"\.\./"),                                                     "attack_type": "Path Traversal", "confidence": 0.85},
    {"pattern": _c(r"%2e%2e%2f", ),                                               "attack_type": "Path Traversal", "confidence": 0.95},  # URL-encoded ../
    {"pattern": _c(r"%252e%252e%252f"),                                            "attack_type": "Path Traversal", "confidence": 0.97},  # Double-encoded
    {"pattern": _c(r"/etc/passwd"),                                                "attack_type": "Path Traversal", "confidence": 0.94},
    {"pattern": _c(r"/etc/shadow"),                                                "attack_type": "Path Traversal", "confidence": 0.94},
    {"pattern": _c(r"/etc/hosts\b"),                                               "attack_type": "Path Traversal", "confidence": 0.90},
    {"pattern": _c(r"C:\\\\(Windows|boot\.ini|System32)"),                        "attack_type": "Path Traversal", "confidence": 0.94},
    {"pattern": _c(r"/proc/self/environ"),                                         "attack_type": "Path Traversal", "confidence": 0.94},
    {"pattern": _c(r"\.\.[/\\\\]"),                                                "attack_type": "Path Traversal", "confidence": 0.88},
]

# ===========================================================================
# 5. DIRECTORY / RESOURCE ENUMERATION
# ===========================================================================
DIRECTORY_ENUMERATION_RULES: list[Rule] = [
    {"pattern": _c(r"^(/admin|/administrator|/phpmyadmin)(/|$)"),                 "attack_type": "Directory Enumeration", "confidence": 0.85},
    {"pattern": _c(r"/\.env\b"),                                                  "attack_type": "Directory Enumeration", "confidence": 0.95},
    {"pattern": _c(r"/\.git(/|$)"),                                               "attack_type": "Directory Enumeration", "confidence": 0.95},
    {"pattern": _c(r"/\.htaccess\b"),                                             "attack_type": "Directory Enumeration", "confidence": 0.93},
    {"pattern": _c(r"/\.DS_Store\b"),                                             "attack_type": "Directory Enumeration", "confidence": 0.90},
    {"pattern": _c(r"/server-status\b"),                                          "attack_type": "Directory Enumeration", "confidence": 0.95},
    {"pattern": _c(r"/wp-admin(/|$)"),                                            "attack_type": "Directory Enumeration", "confidence": 0.88},
    {"pattern": _c(r"/wp-login\.php"),                                            "attack_type": "Directory Enumeration", "confidence": 0.88},
    {"pattern": _c(r"/(config|configuration)\.(php|xml|json|yml|yaml)\b"),        "attack_type": "Directory Enumeration", "confidence": 0.90},
    {"pattern": _c(r"/backup[s]?[\./]"),                                          "attack_type": "Directory Enumeration", "confidence": 0.85},
    {"pattern": _c(r"/(shell|webshell|cmd|c99|r57)\.(php|asp|aspx|jsp)\b"),      "attack_type": "Directory Enumeration", "confidence": 0.99},
    {"pattern": _c(r"/(robots\.txt|sitemap\.xml)\b"),                             "attack_type": "Directory Enumeration", "confidence": 0.60},
]

# ===========================================================================
# 6. BROKEN ACCESS CONTROL
# ===========================================================================
BROKEN_ACCESS_RULES: list[Rule] = [
    {"pattern": _c(r"X-Forwarded-For\s*:\s*127\.0\.0\.1"),                       "attack_type": "Broken Access Control", "confidence": 0.88},
    {"pattern": _c(r"X-Remote-IP\s*:\s*(127\.0\.0\.1|::1|localhost)"),            "attack_type": "Broken Access Control", "confidence": 0.90},
    {"pattern": _c(r"X-Original-URL\s*:"),                                        "attack_type": "Broken Access Control", "confidence": 0.85},
    {"pattern": _c(r"X-Rewrite-URL\s*:"),                                         "attack_type": "Broken Access Control", "confidence": 0.85},
    {"pattern": _c(r"\b(id|user_id|role|admin|is_admin)\s*=\s*\d+\b"),           "attack_type": "Broken Access Control", "confidence": 0.75},  # IDOR
    {"pattern": _c(r"/api/v\d+/(admin|internal|system|management)"),              "attack_type": "Broken Access Control", "confidence": 0.82},
    {"pattern": _c(r"\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9\-_\.]+\b"),      "attack_type": "Broken Access Control", "confidence": 0.55},  # JWT attempts (low)
]

# ===========================================================================
# 7. AUTHENTICATION FAILURE / CREDENTIAL STUFFING
# ===========================================================================
AUTH_FAILURE_RULES: list[Rule] = [
    {"pattern": _c(r"(username|user|login)\s*[=:]\s*(admin|root|administrator|test|guest)"), "attack_type": "Authentication Failure", "confidence": 0.80},
    {"pattern": _c(r"password\s*[=:]\s*(password|1234|12345|123456|admin|root|test|pass|letmein)"), "attack_type": "Authentication Failure", "confidence": 0.85},
    {"pattern": _c(r"\b(admin:admin|root:root|test:test|admin:password|root:toor)\b"),         "attack_type": "Authentication Failure", "confidence": 0.92},
    {"pattern": _c(r"(user|pass)\s*=\s*('|\")?\s*('|\")?;?\s*(--|#)"),                        "attack_type": "Authentication Failure", "confidence": 0.90},  # SQLi in auth
    {"pattern": _c(r"grant_type\s*=\s*password"),                                              "attack_type": "Authentication Failure", "confidence": 0.65},  # OAuth brute
]


# ===========================================================================
# MASTER RULE REGISTRY
# Ordered by specificity — higher-confidence categories first
# ===========================================================================
ALL_RULES: list[Rule] = (
    SQL_INJECTION_RULES
    + COMMAND_INJECTION_RULES
    + PATH_TRAVERSAL_RULES
    + XSS_RULES
    + DIRECTORY_ENUMERATION_RULES
    + BROKEN_ACCESS_RULES
    + AUTH_FAILURE_RULES
)
