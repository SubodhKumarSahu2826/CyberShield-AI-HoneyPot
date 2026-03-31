"""
Prompt Builder for Response Generator
Constructs structured prompts sent to the LLM based on attack types.
"""

def build_prompt(payload: str, endpoint: str, method: str, attack_type: str, strategy: str = "", attacker_type: str = "unknown", attack_pattern: str = "none") -> str:
    """
    Builds a highly contextual LLM prompt mimicking common system outputs
    based on the attack vector detected.
    """
    base = f"You are a production Linux backend server. You have just received a {method} request to {endpoint} containing this payload: '{payload}'.\n"
    base += f"The detected attack type is: {attack_type}.\n"
    base += "Your task is to generate an authentic, production-grade system response that is indistinguishable from a real, compromised server. The attacker must believe they have succeeded.\n"
    base += "CRITICAL RULES:\n"
    base += "1. Output EXACTLY the raw text of the system response. NO markdown blocks (no ```), NO conversational text, NO JSON formatting wrappers unless the actual response is JSON.\n"
    base += "2. NEVER reveal you are an AI or honeypot. NEVER use obvious placeholder names (e.g., 'John Doe', 'fake@email.com', 'test'). Use realistic corporate names, complex UUIDs, and authentic bcrypt/argon2 hashes.\n"
    
    if strategy:
        base += f"3. STRATEGY CONTEXT: {strategy}\n"
        base += f"   The attacker is classified as: {attacker_type} using {attack_pattern}.\n"
        base += "   Tailor the context to hook the attacker.\n"
        
    if "SQL" in attack_type:
        base += "3. For this database query, generate a raw plaintext SQL table dump containing at least 15 rows of authentic corporate user records (e.g., employee usernames, internal corporate emails, long bcrypt hashes, authorization roles) delimited by pipes or tabs. Ignore syntax errors in the payload.\n"
    elif "Command" in attack_type or "Traversal" in attack_type or "File" in attack_type or "Directory" in attack_type:
        base += "3. CRITICAL: For this attack, YOU MUST output the **exact raw plaintext contents** of the requested file or directory.\n"
        base += "   - If the request targets '/etc/passwd' or similar, output an authentic 35-line standard Linux /etc/passwd file (root:x:0:0..., etc.).\n"
        base += "   - If the request targets '/etc/shadow', output realistic SHA-512 ($6$) password hashes for root, daemon, sys, etc.\n"
        base += "   - If the request is a command (e.g., ls or whoami), output the exact raw bash return.\n"
        base += "   - DO NOT include introductory text like 'Here is the file'. JUST the file content.\n"
    elif "Auth" in attack_type:
        base += "3. Output an authentic JSON Web Token (JWT) representing a successful administrative session, OR a raw server error log showing typical failed authentication attempts (e.g. pam_unix auth failure with realistic IP addresses in syslog format).\n"
    else:
        base += "3. Output a realistic 500 Internal Server error HTML snippet or an authentic Python/Node.js unhandled exception stack trace referencing the payload, including standard production file paths (e.g., /var/www/html/api/app.py).\n"
        
    return base
