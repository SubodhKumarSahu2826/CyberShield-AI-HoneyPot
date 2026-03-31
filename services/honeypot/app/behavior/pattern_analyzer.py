def analyze_patterns(session) -> str:
    """Analyze the session history for attack patterns."""
    endpoints = len(session.endpoints_hit)
    requests = session.request_count
    
    if requests > 20 and endpoints < 3 and "SQL Injection" in session.attack_types:
        return "sql_fuzzing"
    if endpoints > 5 and requests > 10:
        if "SQL Injection" in session.attack_types:
            return "automated_sqli_scanner"
        return "directory_scan"
    if requests > 5 and ("/login" in session.endpoints_hit or "/admin" in session.endpoints_hit):
        return "brute_force"
    if requests > 10:
        return "persistent_attacker"
    if requests <= 3 and len(session.attack_types) == 0:
        return "recon"
        
    return "script_kiddie"
