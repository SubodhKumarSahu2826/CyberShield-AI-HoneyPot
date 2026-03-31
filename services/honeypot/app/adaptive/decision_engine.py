from app.adaptive.strategy_manager import get_strategy

def decide_response_strategy(session) -> str:
    """Make a decision on the response strategy to feed to the LLM."""
    if not hasattr(session, 'attacker_type') or not session.attacker_type:
        return "low_sophistication: Return standard minimal dummy responses."
        
    return get_strategy(session.attacker_type, session.attack_pattern)
