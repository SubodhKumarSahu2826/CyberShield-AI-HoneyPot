"""
Async Pipeline: Classification Worker
services/honeypot/app/async_pipeline/classification_worker.py

Background worker that consumes items from the queue_manager,
queries the remote LLM microservice, and asynchronously updates
the main database.

Enhanced (Evasion Defense): When the LLM catches an attack that
bypassed the rule-based engine, the worker upgrades the DB record
to "malicious" AND triggers deception response generation so the
attack appears fully processed in the dashboard.
"""

import asyncio
import httpx
from app.logger import get_logger
from app.async_pipeline.queue_manager import manager
from app.classifier_client import ai_classify
from app.database import update_request_classification, update_request_response

slogger = get_logger()

RESPONSE_GEN_URL = "http://response-generator:3002/generate-response"
RESPONSE_GEN_TIMEOUT = 90.0


async def _generate_deception_response(job, ai_type: str) -> dict | None:
    """
    Call the response-generator service to produce a convincing fake
    response for an attack that the LLM caught but the rules missed.
    Returns the response dict or None on failure.
    """
    try:
        async with httpx.AsyncClient(timeout=RESPONSE_GEN_TIMEOUT) as client:
            res = await client.post(
                RESPONSE_GEN_URL,
                json={
                    "payload": job.payload,
                    "endpoint": job.endpoint,
                    "method": job.method,
                    "attack_type": ai_type,
                    "session_id": job.session_id,
                    "strategy": "high_sophistication: Attacker evaded rule engine — deploy maximum deception.",
                    "attacker_type": "evasion_specialist",
                    "attack_pattern": "rule_bypass",
                },
            )
            if res.status_code == 200:
                return res.json()
    except Exception as exc:  # noqa: BLE001
        slogger.warning(
            f"Deception response generation failed for request {job.request_id}: {exc}",
            extra={"event_type": "response_gen_error"},
        )
    return None


async def worker_loop(worker_id: int):
    """
    Infinite loop that polls the queue_manager.
    Runs persistently inside the honeypot container.

    For EVERY request (safe, suspicious, malicious from rules):
      1. Send to AI classifier for a second opinion.
      2. If AI says "malicious" → upgrade DB status.
      3. If the request was previously "safe" → also generate a
         deception response so the dashboard shows the full attack.
    """
    slogger.info(f"AI Classification Worker [{worker_id}] started.")
    
    while True:
        try:
            job = await manager.dequeue()
            
            # Send to AI Classifier asynchronously
            ai_result = await ai_classify(
                method=job.method,
                endpoint=job.endpoint,
                headers=job.headers,
                payload=job.payload,
            )
            
            # Parse results
            ai_status = getattr(ai_result, "ai_classification_status", "benign")
            ai_type = ai_result.ai_attack_type
            ai_score = ai_result.ai_confidence_score

            # Skip DB update if AI says benign and model is available
            if ai_status == "benign" and ai_type != "model_unavailable":
                slogger.debug(
                    f"Worker [{worker_id}] — AI confirmed benign for request {job.request_id}, no upgrade needed.",
                )
                continue

            # Formulate final status: if AI says malicious, overwrite any prior status
            final_status = "malicious" if ai_status == "malicious" else "suspicious"
            
            # Update DB with AI classification
            await update_request_classification(
                request_id=job.request_id,
                detection_status=final_status,
                ai_attack_type=ai_type,
                ai_confidence_score=ai_score,
            )

            # If AI caught a malicious request, also generate a deception response
            # so the dashboard shows the full attack chain (even though the real-time
            # HTTP response was already sent as a static fallback).
            if final_status == "malicious":
                slogger.warning(
                    f"Worker [{worker_id}] — LLM CAUGHT EVASION ATTACK for request {job.request_id}: {ai_type} (score={ai_score})",
                    extra={
                        "event_type": "evasion_detected",
                        "request_id": job.request_id,
                        "ai_attack_type": ai_type,
                    },
                )
                # Generate and persist a deception response for dashboard visibility
                resp_data = await _generate_deception_response(job, ai_type)
                if resp_data:
                    await update_request_response(
                        request_id=job.request_id,
                        response=resp_data.get("response", ""),
                        response_type=resp_data.get("response_type", "ai_deception"),
                    )
                    slogger.info(
                        f"Worker [{worker_id}] — Deception response stored for request {job.request_id}",
                    )

            slogger.info(
                f"Worker [{worker_id}] completed job {job.request_id}",
                extra={
                    "event_type": "classification_completed",
                    "request_id": job.request_id,
                    "worker_id": worker_id,
                    "classification_status": final_status,
                    "ai_attack_type": ai_type,
                    "ai_confidence_score": ai_score,
                }
            )
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            slogger.error(
                f"Worker [{worker_id}] encountered an error: {exc}",
                extra={"event_type": "classification_error"}
            )
        finally:
            # Always mark task done if we popped it
            try:
                manager.task_done()
            except ValueError:
                pass


async def start_worker_pool(num_workers: int = 3):
    """Spawn a given number of parallel async workers."""
    workers = []
    for i in range(1, num_workers + 1):
        worker = asyncio.create_task(worker_loop(i))
        workers.append(worker)
    return workers
