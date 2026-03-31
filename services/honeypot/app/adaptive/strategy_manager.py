def get_strategy(attacker_type: str, attack_pattern: str) -> str:
    """Returns a high-level deception strategy for the LLM based on attacker sophistication."""
    if attacker_type == "bot":
        return "low_sophistication: Return simple HTTP error pages or generic backend exceptions. Keep it brief."
    elif attacker_type == "intermediate":
        if attack_pattern in ["sql_fuzzing", "automated_sqli_scanner"]:
            return "medium_sophistication: Return seemingly realistic database output frames or mock ORM errors."
        elif attack_pattern == "directory_scan":
            return "medium_sophistication: Expose slightly sensitive-looking fake config files or server headers."
        return "medium_sophistication: Return standard application error traces mimicking a Python or Node backend."
    elif attacker_type == "advanced":
        return "high_sophistication: Return highly detailed fake system data. Expose simulated shell outputs, mock passwd files, or fake AWS credentials in error dumps to waste their time."
        
    return "low_sophistication: Return standard minimal dummy responses."
