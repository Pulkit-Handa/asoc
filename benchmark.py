import asyncio
import time
from uuid import uuid4

# Mock classes to run without full DB
class Incident:
    def __init__(self, **kwargs):
        pass

class MockSession:
    def merge(self, obj):
        time.sleep(0.01)  # Mock blocking I/O (10ms)
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def get_session():
    return MockSession()

def persist_sync(alert_id, values, elapsed_ms):
    with get_session() as session:
        session.merge(Incident(
            alert_id=alert_id,
            threat_category=values.get("threat_category", "UNKNOWN"),
            severity_score=values.get("severity_score", 0.0),
            confidence_score=values.get("confidence_score", 0.0),
            blast_radius=values.get("blast_radius", 0),
            exposure_score=values.get("exposure_score", 0.0),
            decision=values.get("decision", "MONITOR"),
            mitre_techniques=",".join(values.get("mitre_techniques", [])),
            escalation_reason=values.get("escalation_reason"),
            processing_time_ms=elapsed_ms,
            src_ip=values.get("src_ip"),
            host_id=values.get("host_id"),
        ))

async def run_sync_pipeline(n):
    values = {"threat_category": "TEST"}
    t0 = time.monotonic()
    tasks = []

    async def worker():
        # original blocking code
        persist_sync(uuid4().hex, values, 100)

    await asyncio.gather(*(worker() for _ in range(n)))
    return time.monotonic() - t0

async def run_async_pipeline(n):
    from fastapi.concurrency import run_in_threadpool
    values = {"threat_category": "TEST"}
    t0 = time.monotonic()

    async def worker():
        await run_in_threadpool(persist_sync, uuid4().hex, values, 100)

    await asyncio.gather(*(worker() for _ in range(n)))
    return time.monotonic() - t0

async def main():
    n = 100
    print("Running baseline (blocking)...")
    t_sync = await run_sync_pipeline(n)
    print(f"Baseline: {t_sync:.2f}s")

    # We can't actually run run_async_pipeline here if fastapi is not available, but let's test if asyncio.to_thread works
    print("Running optimized (threadpool mock)...")
    values = {"threat_category": "TEST"}
    t0 = time.monotonic()
    async def worker():
        await asyncio.to_thread(persist_sync, uuid4().hex, values, 100)
    await asyncio.gather(*(worker() for _ in range(n)))
    t_async = time.monotonic() - t0
    print(f"Optimized: {t_async:.2f}s")

if __name__ == "__main__":
    asyncio.run(main())
