"""
Alert Manager - Milestone 3
Evaluates session data and triggers alerts if security thresholds are breached.
"""

from app.logger import get_logger
from app.logging.structured_logger import log_event, get_structured_logger
from app.database import insert_alert
from app.alerts.channels import send_email_alert, send_webhook_alert
from app.security.firewall_rules import block_ip

logger = get_logger()
slogger = get_structured_logger()

async def check_and_trigger_alerts(
    source_ip: str, 
    session_id: str, 
    attack_type: str, 
    attacker_score: float, 
    request_count: int
) -> None:
    """
    Evaluates thresholds. Triggers events dynamically and updates the DB.
    """
    severity = ""
    message = ""
    
    if attacker_score >= 9.0:
        severity = "critical"
        message = f"Critical sophistication threshold breached! Score: {attacker_score:.1f}"
    elif request_count > 100:
        severity = "high"
        message = f"High request volume detected: {request_count} requests in session."
    elif attack_type in ["SQL Injection", "Command Injection"]:
        severity = "medium"
        message = f"Severe attack signature payload detected: {attack_type}."
        
    if not severity:
        return
        
    # Log structured event
    log_event(
        slogger,
        event="alert_triggered",
        source_ip=source_ip,
        session_id=session_id,
        attack_type=attack_type,
        severity=severity,
        alert_message=message
    )
    
    logger.warning(f"Alert Triggered! [{severity.upper()}] {message}")
    
    try:
        # Insert persistent alert to DB
        await insert_alert(
            source_ip=source_ip,
            session_id=session_id,
            attack_type=attack_type,
            severity=severity,
            message=message
        )
    except Exception as e:
        logger.error(f"Failed to insert alert into DB: {e}")
    
    # Broadcast via channels
    alert_payload = {
        "source_ip": source_ip,
        "attack_type": attack_type,
        "severity": severity,
        "message": message
    }
    
    if severity in ["high", "critical"]:
        await send_webhook_alert(alert_payload)
    if severity == "critical":
        await send_email_alert(alert_payload)
        # Honeypot philosophy: NEVER block attackers. We WANT them to keep
        # talking so we can collect maximum intelligence and behavioural data.
        # await block_ip(source_ip)  # Disabled — honeypots trap, not block
        logger.warning(f"IP {source_ip} triggered critical alert — continuing to trap for intelligence.")
