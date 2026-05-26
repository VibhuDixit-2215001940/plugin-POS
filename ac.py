import requests
import threading
import time

TARGET = "https://music.amazon.com"
THREADS = 50
REQUESTS_PER_THREAD = 20

success = 0
failed = 0

lock = threading.Lock()

def hit():
    global success, failed

    for _ in range(REQUESTS_PER_THREAD):
        try:
            start = time.time()

            r = requests.get(
                TARGET,
                timeout=5
            )

            elapsed = round(time.time() - start, 2)

            with lock:
                print(f"[{r.status_code}] {elapsed}s")

                if r.status_code < 500:
                    success += 1
                else:
                    failed += 1

        except Exception as e:
            with lock:
                failed += 1
                print(f"[ERROR] {e}")

threads = []

for _ in range(THREADS):
    t = threading.Thread(target=hit)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("\n====== RESULT ======")
print(f"Successful Requests : {success}")
print(f"Failed Requests     : {failed}")
print(f"Total Requests      : {THREADS * REQUESTS_PER_THREAD}")