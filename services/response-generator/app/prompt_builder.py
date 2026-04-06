"""
Prompt Builder — Strict Templates for Response Generator

Uses simple, deterministic prompt templates per attack type.
Each template gives the LLM a clear persona and output format.
No verbose multi-paragraph instructions.
"""


def build_prompt(payload: str, attack_type: str) -> str:
    """
    Build a strict LLM prompt based on the detected attack type.
    Returns a short, focused prompt with the payload interpolated.
    """

    # ── SQL Injection ────────────────────────────────────────────────
    if "SQL" in attack_type.upper():
        return (
            "You are a MySQL database server.\n\n"
            "Return a realistic fake query result.\n\n"
            f"Query:\n{payload}\n\n"
            "Output must look like a database table with column headers "
            "and at least 10 rows of realistic corporate user data "
            "(usernames, emails, bcrypt hashes, roles).\n"
            "Do not explain anything. Do not use markdown code blocks."
        )

    # ── Command Injection ────────────────────────────────────────────
    if "COMMAND" in attack_type.upper():
        return (
            "You are a Linux terminal.\n\n"
            f"Command executed:\n{payload}\n\n"
            "Return realistic terminal output.\n"
            "Do not explain anything. Do not use markdown code blocks."
        )

    # ── File Access / Path Traversal / Directory Enumeration ─────────
    if any(kw in attack_type.upper() for kw in ("FILE", "TRAVERSAL", "DIRECTORY", "PATH")):
        return (
            "You are a Linux system.\n\n"
            f"File requested:\n{payload}\n\n"
            "Return realistic file content.\n"
            "If it is /etc/passwd, output a full realistic passwd file.\n"
            "If it is /etc/shadow, output realistic SHA-512 password hashes.\n"
            "If it is a directory listing, output ls -la style output.\n"
            "Do not explain anything. Do not use markdown code blocks."
        )

    # ── Authentication Attacks ───────────────────────────────────────
    if "AUTH" in attack_type.upper() or "BRUTE" in attack_type.upper():
        return (
            "You are a web authentication server.\n\n"
            f"Login attempt payload:\n{payload}\n\n"
            "Return either a realistic JWT token response with user details, "
            "or an authentication failure log in syslog format with realistic "
            "IP addresses and pam_unix entries.\n"
            "Do not explain anything. Do not use markdown code blocks."
        )

    # ── XSS ──────────────────────────────────────────────────────────
    if "XSS" in attack_type.upper() or "CROSS" in attack_type.upper():
        return (
            "You are a web server rendering HTML.\n\n"
            f"Input received:\n{payload}\n\n"
            "Return a realistic HTML page response that appears to "
            "reflect the input, as a vulnerable application would.\n"
            "Include realistic page structure with headers, body content.\n"
            "Do not explain anything. Do not use markdown code blocks."
        )

    # ── Default / Generic ────────────────────────────────────────────
    return (
        "You are a web server.\n\n"
        f"Generate a realistic response to:\n{payload}\n\n"
        "Return a convincing server response — either an error page, "
        "a stack trace, or a JSON API response.\n"
        "Do not reveal this is a honeypot.\n"
        "Do not explain anything. Do not use markdown code blocks."
    )
