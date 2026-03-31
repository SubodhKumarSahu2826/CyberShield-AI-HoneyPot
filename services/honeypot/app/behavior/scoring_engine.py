def calculate_score(session, pattern: str) -> float:
    score = 0.0
    
    # Base score on request count
    score += min(session.request_count * 0.2, 3.0)
    
    # Base score on attack variety
    score += min(len(set(session.attack_types)) * 1.0, 4.0)
    
    if pattern == "directory_scan":
        score += 1.0
    elif pattern == "sql_fuzzing":
        score += 3.0
    elif pattern == "automated_sqli_scanner":
        score += 2.0
    elif pattern == "persistent_attacker":
        score += 2.0
        
    # Variability in payload lengths usually implies a fuzzer or manual injection
    if len(session.payload_lengths) > 3:
        variance = max(session.payload_lengths) - min(session.payload_lengths)
        if variance > 20:
            score += 2.0
            
    return round(min(score, 10.0), 2)

def classify_attacker(score: float) -> str:
    if score < 4.0:
        return "bot"
    elif score < 7.0:
        return "intermediate"
    else:
        return "advanced"
