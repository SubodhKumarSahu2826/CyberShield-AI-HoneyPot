"""
Alert Channels for Milestone 3
Configures asynchronous email and webhook dispatches.
"""
from app.logger import get_logger

logger = get_logger()

async def send_email_alert(alert_data: dict) -> None:
    """Stub for sending an email alert via SMTP."""
    logger.info(f"[EMAIL ALERT DISPATCHED] {alert_data.get('attack_type')} from {alert_data.get('source_ip')}")

async def send_webhook_alert(alert_data: dict) -> None:
    """Stub for sending a JSON webhook to Slack/Discord."""
    logger.info(f"[WEBHOOK DEPLOYED] Severity {alert_data.get('severity')} event: {alert_data.get('message')}")
