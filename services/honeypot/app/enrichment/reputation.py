from app.logger import get_logger

logger = get_logger()

# Naive mapping to mock IP reputation since free real threat feeds require API keys.
# We will flag specific common abusive subnets or signatures as mock reputation.
_KNOWN_BAD_SUBNETS = [
    "185.", "193.", "45.", "89." # Synthetic bad actor blocks for testing
]

async def get_reputation(ip: str, attack_type: str) -> dict:
    """
    Determine IP reputation based on mock logic.
    Returns:
        {"reputation_score": int (0-100), "reputation_tags": list of str}
    """
    if ip in ("127.0.0.1", "localhost", "0.0.0.0", "unknown"):
        return {"reputation_score": 0, "reputation_tags": []}

    score = 0
    tags = []

    # Simple heuristic 1: Known 'bad' ASNs/subnets (Mocked)
    for subnet in _KNOWN_BAD_SUBNETS:
        if ip.startswith(subnet):
            score += 30
            tags.append("known_abuser")
            break

    # Simple heuristic 2: What attack are they trying right now?
    if attack_type != "unknown":
        score += 40
        tags.append(attack_type.lower().replace(" ", "_"))

    if score > 0:
        logger.debug(f"Reputation flagged for {ip}: Score {score}, Tags {tags}")

    return {
        "reputation_score": min(score, 100),
        "reputation_tags": tags
    }
