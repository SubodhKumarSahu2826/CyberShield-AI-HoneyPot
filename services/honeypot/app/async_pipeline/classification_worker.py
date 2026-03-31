"""
Async Pipeline: Classification Worker
services/honeypot/app/async_pipeline/classification_worker.py

Background worker that consumes items from the queue_manager,
queries the remote LLM microservice, and asynchronously updates
the main database.
"""

import asyncio
from app.logger import get_logger
from app.async_pipeline.queue_manager import manager
from app.classifier_client import ai_classify
from app.database import update_request_classification

slogger = get_logger()

async def worker_loop(worker_id: int):
    """
    Infinite loop that polls the queue_manager.
    Runs persistently inside the honeypot container.
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
            
            # Formulate final status (if AI says malicious, overwrite 'suspicious')
            final_status = "malicious" if ai_status == "malicious" else "suspicious"
            
            # Update DB
            await update_request_classification(
                request_id=job.request_id,
                detection_status=final_status,
                ai_attack_type=ai_type,
                ai_confidence_score=ai_score,
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
