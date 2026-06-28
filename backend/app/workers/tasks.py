import os
import sys
import threading
import logging
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("cyberagent.worker")

# Define ThreadPoolExecutor fallback for running background scans without Redis/Celery
executor = ThreadPoolExecutor(max_workers=5)

# Try loading Celery if configured in system
try:
    from celery import Celery
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    celery_app = Celery("cyberagent", broker=REDIS_URL, backend=REDIS_URL)
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    celery_app = None

def trigger_background_scan(scan_id: int, simulation: bool = True):
    """Triggers background orchestration task. Uses Celery if available, otherwise falls back to ThreadPoolExecutor."""
    from app.agents.workflow import orchestrate_scan
    
    if CELERY_AVAILABLE:
        try:
            logger.info(f"Enqueuing scan {scan_id} to Celery worker.")
            run_scan_task.delay(scan_id, simulation)
            return
        except Exception as e:
            logger.warning(f"Failed to submit task to Celery: {e}. Falling back to ThreadPoolExecutor.")
            
    logger.info(f"Enqueuing scan {scan_id} to background ThreadPoolExecutor.")
    executor.submit(orchestrate_scan, scan_id, simulation)

if CELERY_AVAILABLE:
    @celery_app.task(name="cyberagent.run_scan_task")
    def run_scan_task(scan_id: int, simulation: bool = True):
        from app.agents.workflow import orchestrate_scan
        orchestrate_scan(scan_id, simulation)
