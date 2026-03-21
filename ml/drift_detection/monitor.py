"""
Model Drift Detection — Population Stability Index
====================================================
Monitors SecBERT classification distribution weekly.
PSI > 0.20 triggers fine-tuning refresh and Prometheus alert.

PSI interpretation:
  < 0.10  No drift — model is stable
  0.10-0.20  Moderate drift — monitor closely
  > 0.20  Significant drift — trigger fine-tune cycle
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import List

import numpy as np
from prometheus_client import Gauge, push_to_gateway

logger = logging.getLogger(__name__)

PSI_GAUGE = Gauge("asoc_model_drift_psi", "Population Stability Index for SecBERT", ["model"])

PSI_WARNING   = 0.10
PSI_CRITICAL  = 0.20
BUCKETS       = 10


def compute_psi(
    expected_dist: List[float],
    actual_dist:   List[float],
    buckets:       int = BUCKETS,
) -> float:
    """
    Compute Population Stability Index between expected and actual distributions.

    PSI = Σ (Actual% - Expected%) × ln(Actual% / Expected%)
    
    Higher PSI = more distributional shift in incoming threat landscape.
    """
    eps = 1e-10  # Prevent log(0)

    expected_arr = np.array(expected_dist, dtype=float)
    actual_arr   = np.array(actual_dist,   dtype=float)

    expected_pct = (np.histogram(expected_arr, bins=buckets)[0] + eps) / len(expected_arr)
    actual_pct   = (np.histogram(actual_arr,   bins=buckets)[0] + eps) / len(actual_arr)

    # Normalize
    expected_pct /= expected_pct.sum()
    actual_pct   /= actual_pct.sum()

    psi = float(np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct)))
    return round(psi, 6)


def fetch_classification_distribution(days: int, reference: bool = False):
    """
    Fetch SecBERT output probability distributions from ClickHouse.
    reference=True: fetch the baseline (first 30 days of production).
    reference=False: fetch the most recent `days` window.
    """
    from agents.forensics.clickhouse_client import get_client

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    if reference:
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)  # GA launch baseline

    client = get_client()
    rows = client.execute(
        "SELECT confidence_score FROM asoc_decisions "
        "WHERE created_at >= %(cutoff)s",
        {"cutoff": cutoff.strftime("%Y-%m-%d")},
    )
    return [row[0] for row in rows]


def run_weekly_drift_check():
    """
    Weekly CronJob entry point.
    Compare last 7 days against baseline; alert if PSI > 0.20.
    """
    logger.info("Starting weekly PSI drift check...")

    baseline = fetch_classification_distribution(days=30, reference=True)
    current  = fetch_classification_distribution(days=7)

    if len(baseline) < 100 or len(current) < 50:
        logger.warning(
            "Insufficient data for PSI: baseline=%d current=%d — skipping",
            len(baseline), len(current),
        )
        return

    psi = compute_psi(baseline, current)
    PSI_GAUGE.labels(model="secbert").set(psi)

    if psi >= PSI_CRITICAL:
        logger.critical(
            "CRITICAL DRIFT: PSI=%.4f (>%.2f) — triggering fine-tune cycle",
            psi, PSI_CRITICAL,
        )
        _trigger_finetune_pipeline()
    elif psi >= PSI_WARNING:
        logger.warning("MODERATE DRIFT: PSI=%.4f (%.2f-%.2f) — monitoring", psi, PSI_WARNING, PSI_CRITICAL)
    else:
        logger.info("NO DRIFT: PSI=%.4f (<%.2f) — model is stable", psi, PSI_WARNING)

    # Push to Prometheus Pushgateway
    pushgateway = os.getenv("PROMETHEUS_PUSHGATEWAY", "localhost:9091")
    try:
        push_to_gateway(pushgateway, job="asoc-drift-monitor", registry=PSI_GAUGE._metrics)
    except Exception as exc:
        logger.warning("Failed to push PSI metric: %s", exc)

    return psi


def _trigger_finetune_pipeline():
    """Trigger the MLflow/Kubeflow fine-tuning pipeline via API call."""
    import requests
    pipeline_url = os.getenv("FINETUNE_PIPELINE_URL", "http://kubeflow:8888/pipeline/run")
    try:
        resp = requests.post(pipeline_url, json={
            "pipeline": "secbert-finetune",
            "trigger":  "drift_detection",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, timeout=10)
        resp.raise_for_status()
        logger.info("Fine-tune pipeline triggered: %s", resp.json())
    except Exception as exc:
        logger.error("Failed to trigger fine-tune pipeline: %s", exc)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_weekly_drift_check()
