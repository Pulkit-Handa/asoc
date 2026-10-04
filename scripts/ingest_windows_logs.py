import argparse
import asyncio
import json
import logging
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor

import httpx

from config.settings import cfg

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def extract_ips(text: str) -> list[str]:
    """Naive regex to find IPv4 addresses in text."""
    pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    return re.findall(pattern, text)


def fetch_windows_logs(log_name: str = "System", limit: int = 1000) -> list[dict]:
    """Fetches Windows Event Logs using PowerShell."""
    logger.info(f"Fetching up to {limit} {log_name} logs from Windows...")
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-Command",
        f"Get-WinEvent -LogName {log_name} -MaxEvents {limit} -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2 -Compress"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        if not result.stdout.strip():
            return []
        
        # In PowerShell, if it's a single item, it won't be an array.
        output = result.stdout.strip()
        if output.startswith("{"):
            output = f"[{output}]"
            
        logs = json.loads(output)
        return logs
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to fetch {log_name} logs: {e.stderr}")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON for {log_name}: {e}")
        return []


async def send_log_to_asoc(client: httpx.AsyncClient, event: dict, api_key: str):
    """Parses a Windows Event Log entry and sends it to the ASOC API."""
    message = event.get("Message") or event.get("Id", "Unknown Event")
    machine_name = event.get("MachineName", "localhost")
    
    ips = extract_ips(str(message))
    src_ip = ips[0] if ips else None
    dst_ip = ips[1] if len(ips) > 1 else None
    
    user = event.get("UserId", {}).get("Value") if isinstance(event.get("UserId"), dict) else None
    
    payload = {
        "raw_log": f"Windows Event ({event.get('LogName')} - ID: {event.get('Id')}): {message}",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "user": user,
        "host_id": machine_name,
        "source": "windows_event_log",
    }
    
    headers = {"X-API-Key": api_key}
    
    try:
        response = await client.post(
            "http://localhost:8080/alerts",
            json=payload,
            headers=headers,
            timeout=5.0
        )
        if response.status_code == 202:
            return True
        else:
            logger.warning(f"Failed to send alert: {response.status_code} {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error connecting to ASOC API: {e}")
        return False


async def ingest_logs_concurrently(logs: list[dict], concurrency: int = 50, api_key: str = "dev-simulation-key"):
    """Sends logs concurrently to simulate pressure."""
    logger.info(f"Firing {len(logs)} logs at ASOC API with concurrency {concurrency}...")
    
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(limits=limits) as client:
        tasks = [send_log_to_asoc(client, log, api_key) for log in logs]
        
        # Gather results in chunks to avoid overwhelming event loop
        chunk_size = concurrency * 2
        successes = 0
        
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            results = await asyncio.gather(*chunk)
            successes += sum(bool(r) for r in results)
            
        logger.info(f"Done! Successfully sent {successes}/{len(logs)} alerts via HTTP.")


def ingest_logs_kafka(logs: list[dict]):
    """Sends logs directly to Kafka, bypassing the HTTP API completely."""
    import uuid
    from confluent_kafka import Producer
    
    logger.info(f"Producing {len(logs)} logs directly to Kafka (bypassing HTTP)...")
    
    producer = Producer({
        'bootstrap.servers': 'localhost:9092',
        'client.id': 'windows-ingest-script'
    })
    
    success_count = 0
    for event in logs:
        message = event.get("Message") or event.get("Id", "Unknown Event")
        machine_name = event.get("MachineName", "localhost")
        
        ips = extract_ips(str(message))
        src_ip = ips[0] if ips else None
        dst_ip = ips[1] if len(ips) > 1 else None
        user = event.get("UserId", {}).get("Value") if isinstance(event.get("UserId"), dict) else None
        
        payload = {
            "raw_log": f"Windows Event ({event.get('LogName')} - ID: {event.get('Id')}): {message}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "user": user,
            "host_id": machine_name,
            "source": "windows_event_log_direct",
        }
        
        # Produce to the topic
        producer.produce(
            topic="security.raw_logs",
            key=str(uuid.uuid4()).encode('utf-8'),
            value=json.dumps(payload).encode('utf-8')
        )
        success_count += 1
        
        # Periodically poll to serve delivery reports
        if success_count % 1000 == 0:
            producer.poll(0)
            
    # Wait for all messages to be delivered
    producer.flush()
    logger.info(f"Done! Successfully produced {success_count}/{len(logs)} alerts directly to Kafka.")


def main():
    parser = argparse.ArgumentParser(description="Ingest Windows Event Logs into ASOC for load testing")
    parser.add_argument("--limit", type=int, default=1000, help="Number of logs per category to fetch")
    parser.add_argument("--concurrency", type=int, default=50, help="Number of concurrent requests to make")
    parser.add_argument("--api-key", type=str, default="dev-simulation-key", help="API Key for ASOC")
    parser.add_argument("--direct-kafka", action="store_true", help="Bypass HTTP API and write directly to Kafka")
    args = parser.parse_args()

    all_logs = []
    # Fetch from System and Application (Security often requires admin privileges to read)
    for log_name in ["System", "Application"]:
        logs = fetch_windows_logs(log_name=log_name, limit=args.limit)
        all_logs.extend(logs)
        
    if not all_logs:
        logger.error("No logs fetched. Exiting.")
        return
        
    if args.direct_kafka:
        ingest_logs_kafka(all_logs)
    else:
        asyncio.run(ingest_logs_concurrently(all_logs, concurrency=args.concurrency, api_key=args.api_key))


if __name__ == "__main__":
    main()
