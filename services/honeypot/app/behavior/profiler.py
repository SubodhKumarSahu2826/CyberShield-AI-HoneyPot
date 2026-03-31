from app.behavior.pattern_analyzer import analyze_patterns
from app.behavior.scoring_engine import calculate_score, classify_attacker
from app.logging.structured_logger import get_structured_logger

logger = get_structured_logger(__name__)

def update_profile(session, endpoint: str, payload_len: int) -> None:
    """Updates the internal session representation with new behaviour intelligence."""
    # Safety initialization to ensure backward compatibility during hot-reload
    if not hasattr(session, 'endpoints_hit'):
        session.endpoints_hit = set()
    if not hasattr(session, 'payload_lengths'):
        session.payload_lengths = []
        
    session.endpoints_hit.add(endpoint)
    session.payload_lengths.append(payload_len)
    
    # Keep rolling list bounded
    session.payload_lengths = session.payload_lengths[-50:]
    
    pattern = analyze_patterns(session)
    score = calculate_score(session, pattern)
    attacker_type = classify_attacker(score)
    
    # Log significant changes
    if getattr(session, 'attack_pattern', None) != pattern or abs(getattr(session, 'attacker_score', 0.0) - score) > 1.0:
        logger.info(
            f"Profile updated for {session.session_id}: {attacker_type} ({score:.1f}) - {pattern}", 
            extra={
                "event_type": "profile_updated",
                "session_id": session.session_id,
                "attacker_score": score,
                "attacker_type": attacker_type,
                "attack_pattern": pattern
            }
        )
        
    session.attack_pattern = pattern
    session.attacker_score = score
    session.attacker_type = attacker_type
