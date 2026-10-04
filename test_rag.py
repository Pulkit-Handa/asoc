import asyncio
import httpx
import json
import time

API_URL = "http://localhost:8080"
HEADERS = {"Content-Type": "application/json"}

async def test_learning():
    async with httpx.AsyncClient() as client:
        print("=== Step 1: Sending an unknown alert ===")
        payload1 = {
            "raw_log": "Suspicious login attempt from 10.9.8.7 by user rdp_admin at 3AM",
            "src_ip": "10.9.8.7",
            "user": "rdp_admin",
            "process_hash": "b2f5ff47436671b6e533d8dc3614845d",
        }
        
        # 1. Ingest alert
        res1 = await client.post(f"{API_URL}/alerts", json=payload1, headers=HEADERS)
        if res1.status_code != 202:
            print(f"Failed to ingest: {res1.text}")
            return
            
        alert_id1 = res1.json()["alert_id"]
        print(f"[*] Alert ingested! ID: {alert_id1}")
        
        # Wait for pipeline to process it
        print("[*] Polling for pipeline to process...")
        decision1 = None
        for _ in range(60):
            await asyncio.sleep(2)
            res_get = await client.get(f"{API_URL}/incidents/{alert_id1}", headers=HEADERS)
            if res_get.status_code == 200:
                decision1 = res_get.json().get("decision")
                print(f"[*] Initial Decision: {decision1}")
                break
        
        if not decision1:
            print(f"Failed to get incident in time: {res_get.text}")
            return
            
        print("\n=== Step 2: Providing feedback (FALSE_POSITIVE) ===")
        outcome_payload = {
            "confirmed_outcome": "FALSE_POSITIVE",
            "annotation": "This is a known backup script that runs at 3AM."
        }
        res_out = await client.post(f"{API_URL}/incidents/{alert_id1}/outcome", json=outcome_payload, headers=HEADERS)
        print(f"[*] Feedback Response: {res_out.json()}")
        
        print("[*] Polling for Critic Agent to create review...")
        for _ in range(30):
            await asyncio.sleep(2)
            reviews_res = await client.get(f"{API_URL}/reviews", headers=HEADERS)
            if reviews_res.status_code == 200:
                reviews = reviews_res.json()
                found = False
                for r in reviews:
                    if r["alert_id"] == alert_id1:
                        found = True
                        appr_res = await client.post(
                            f"{API_URL}/reviews/{r['id']}/approve", 
                            json={"note": "Approved by test script"},
                            headers=HEADERS
                        )
                        print(f"[*] Approval response: {appr_res.status_code} {appr_res.text}")
                        break
                if found:
                    break
        else:
            print("[-] Could not find review to approve in time!")
            
        print("\n=== Step 3: Sending the same alert again ===")
        # 3. Ingest same alert
        res2 = await client.post(f"{API_URL}/alerts", json=payload1, headers=HEADERS)
        alert_id2 = res2.json()["alert_id"]
        print(f"[*] Alert ingested! ID: {alert_id2}")
        
        # Wait for pipeline to process it
        print("[*] Polling for pipeline to process...")
        decision2 = None
        for _ in range(60):
            await asyncio.sleep(2)
            res_get2 = await client.get(f"{API_URL}/incidents/{alert_id2}", headers=HEADERS)
            if res_get2.status_code == 200:
                decision2 = res_get2.json().get("decision")
                print(f"[*] New Decision: {decision2}")
                break
        
        if not decision2:
            print(f"Failed to get second incident in time: {res_get2.text}")
            
if __name__ == "__main__":
    asyncio.run(test_learning())
