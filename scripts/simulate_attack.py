"""
Red Team Attack Simulator
=========================
Sends realistic multi-stage attack scenarios through the ASOC pipeline.
Use this to test end-to-end behaviour before deploying to production.

Usage:
    python scripts/simulate_attack.py --scenario lateral_movement
    python scripts/simulate_attack.py --scenario ransomware
    python scripts/simulate_attack.py --scenario credential_dump
    python scripts/simulate_attack.py --scenario all
"""
import argparse
import json
import logging
import sys
import time
import os

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)

API_BASE = os.getenv("ASOC_API_URL", "http://localhost:8080")
AUTH_HEADER = {"Authorization": "ApiKey dev-simulation-key"}


# ── Attack scenario definitions ───────────────────────────────────────────────

SCENARIOS = {

    "lateral_movement": [
        {
            "label": "Stage 1: Initial phishing execution",
            "raw_log": "2026-03-12T09:15:01Z host=workstation-07 process=outlook.exe child=powershell.exe args='-WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0' user=jsmith src_ip=192.168.1.107",
            "src_ip": "192.168.1.107", "user": "jsmith", "host_id": "workstation-07",
        },
        {
            "label": "Stage 2: Credential dump attempt",
            "raw_log": "2026-03-12T09:17:33Z host=workstation-07 process=lsass_dump.exe accessing=lsass.exe GrantedAccess=0x1410 src_ip=192.168.1.107 user=jsmith EventID=4656",
            "src_ip": "192.168.1.107", "user": "jsmith", "host_id": "workstation-07",
            "process_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        },
        {
            "label": "Stage 3: Lateral movement via SMB",
            "raw_log": "2026-03-12T09:22:15Z EventID=5140 ShareName=\\\\app-01\\ADMIN$ src_ip=192.168.1.107 user=jsmith dst_ip=10.0.0.11 host_id=app-01 Access=READ WRITE",
            "src_ip": "192.168.1.107", "dst_ip": "10.0.0.11", "user": "jsmith", "host_id": "app-01",
        },
        {
            "label": "Stage 4: Domain controller access",
            "raw_log": "2026-03-12T09:28:44Z EventID=4769 ServiceName=krbtgt ClientAddress=10.0.0.11 user=jsmith TicketEncryptionType=0x17 host_id=dc-01",
            "src_ip": "10.0.0.11", "user": "jsmith", "host_id": "dc-01",
        },
    ],

    "ransomware": [
        {
            "label": "Stage 1: Backup service disabled",
            "raw_log": "2026-03-12T02:03:11Z EventID=7036 ServiceName=VSS CurrentState=Stopped src_ip=10.0.1.55 user=SYSTEM host_id=app-02",
            "src_ip": "10.0.1.55", "host_id": "app-02",
        },
        {
            "label": "Stage 2: Shadow copy deletion",
            "raw_log": "2026-03-12T02:03:45Z process=vssadmin.exe args='delete shadows /all /quiet' user=SYSTEM host_id=app-02 src_ip=10.0.1.55 EventID=4688",
            "src_ip": "10.0.1.55", "host_id": "app-02",
        },
        {
            "label": "Stage 3: Mass file encryption begins",
            "raw_log": "2026-03-12T02:04:02Z process=svchost32.exe renamed_files=2847 extension=.locked src_ip=10.0.1.55 host_id=app-02 writes_per_second=340 user=SYSTEM",
            "src_ip": "10.0.1.55", "host_id": "app-02",
        },
    ],

    "credential_dump": [
        {
            "label": "Stage 1: Recon - domain user enumeration",
            "raw_log": "2026-03-12T14:00:05Z process=cmd.exe args='net user /domain' user=contractor_temp src_ip=192.168.5.22 host_id=workstation-12",
            "src_ip": "192.168.5.22", "user": "contractor_temp", "host_id": "workstation-12",
        },
        {
            "label": "Stage 2: Kerberoasting - bulk TGS requests",
            "raw_log": "2026-03-12T14:01:12Z EventID=4769 multiple_tickets=true count=17 TicketEncryptionType=0x17 ClientAddress=192.168.5.22 user=contractor_temp",
            "src_ip": "192.168.5.22", "user": "contractor_temp",
        },
        {
            "label": "Stage 3: Pass-the-hash with stolen credentials",
            "raw_log": "2026-03-12T14:15:33Z EventID=4624 LogonType=3 AuthPackage=NTLM WorkstationName=unknown src_ip=192.168.5.22 user=svc_backup host_id=db-primary",
            "src_ip": "192.168.5.22", "user": "svc_backup", "host_id": "db-primary",
        },
    ],

    "low_severity_noise": [
        {
            "label": "Routine: Failed login during password change",
            "raw_log": "2026-03-12T10:00:01Z EventID=4625 user=bob.jones src_ip=10.0.2.45 host_id=workstation-03 FailureReason=Wrong Password SubStatus=0xC000006A",
            "src_ip": "10.0.2.45", "user": "bob.jones",
        },
        {
            "label": "Routine: Service account scheduled task",
            "raw_log": "2026-03-12T10:05:00Z EventID=4698 TaskName=\\DailyBackup user=svc_backup host_id=backup-01 CreatedBy=IT_Admin",
            "user": "svc_backup", "host_id": "backup-01",
        },
    ],
}


def send_alert(alert: dict, label: str) -> dict | None:
    """POST an alert to the API and return the response."""
    payload = {
        "raw_log":     alert["raw_log"],
        "src_ip":      alert.get("src_ip"),
        "dst_ip":      alert.get("dst_ip"),
        "user":        alert.get("user"),
        "process_hash": alert.get("process_hash"),
        "host_id":     alert.get("host_id"),
        "source":      "simulation",
    }

    try:
        resp = requests.post(
            f"{API_BASE}/alerts",
            json=payload,
            headers=AUTH_HEADER,
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        logger.info("  ✓ Alert sent: %s → alert_id=%s", label, data["alert_id"])
        return data
    except Exception as exc:
        logger.error("  ✗ Failed to send alert '%s': %s", label, exc)
        return None


def run_scenario(name: str, delay_seconds: float = 2.0):
    """Run a full attack scenario, sending each stage with a delay."""
    stages = SCENARIOS.get(name)
    if not stages:
        logger.error("Unknown scenario: %s. Options: %s", name, list(SCENARIOS.keys()))
        return

    logger.info("\n=== Scenario: %s ===", name.upper().replace("_", " "))
    alert_ids = []

    for i, stage in enumerate(stages, 1):
        logger.info("Stage %d/%d: %s", i, len(stages), stage["label"])
        result = send_alert(stage, stage["label"])
        if result:
            alert_ids.append(result["alert_id"])

        if i < len(stages):
            logger.info("  (waiting %ss before next stage...)", delay_seconds)
            time.sleep(delay_seconds)

    logger.info("\nScenario complete. Alert IDs: %s", alert_ids)
    logger.info("Check results at: %s/incidents", API_BASE)
    return alert_ids


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ASOC Red Team Simulator")
    parser.add_argument("--scenario", default="lateral_movement",
                        choices=list(SCENARIOS.keys()) + ["all"])
    parser.add_argument("--delay",    type=float, default=2.0,
                        help="Seconds between stages")
    args = parser.parse_args()

    # Check API is reachable
    try:
        requests.get(f"{API_BASE}/health", timeout=5)
    except Exception:
        logger.error("ASOC API not reachable at %s — run `make dev` first", API_BASE)
        sys.exit(1)

    if args.scenario == "all":
        for scenario in SCENARIOS:
            run_scenario(scenario, args.delay)
            time.sleep(3)
    else:
        run_scenario(args.scenario, args.delay)
