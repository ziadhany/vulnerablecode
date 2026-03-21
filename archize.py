import json
import time
from datetime import datetime

import requests

# ── CONFIG ────────────────────────────────────────────────────────────────────
URLS = [
    "https://github.com/aboutcode-org/vulnerablecode/issues/17",
]

DELAY_SECONDS = 5  # pause between requests to avoid rate-limiting
LOG_FILE = "archive_log.json"
# ─────────────────────────────────────────────────────────────────────────────

SPN_ENDPOINT = "https://web.archive.org/save/"


def save_url(url: str) -> dict:
    """Submit a single URL to the Wayback Machine."""
    try:
        response = requests.post(
            SPN_ENDPOINT,
            data={"url": url},
            headers={"User-Agent": "ArchiveBot/1.0"},
            timeout=30,
        )

        if response.status_code == 200:
            # Archive.org returns the archived URL in the Content-Location header
            location = response.headers.get("Content-Location", "")
            archived_url = f"https://web.archive.org{location}" if location else "check manually"
            return {"url": url, "status": "success", "archived_url": archived_url}

        else:
            return {
                "url": url,
                "status": "failed",
                "http_code": response.status_code,
                "reason": response.text[:200],
            }

    except requests.exceptions.Timeout:
        return {"url": url, "status": "error", "reason": "Request timed out"}
    except requests.exceptions.RequestException as e:
        return {"url": url, "status": "error", "reason": str(e)}


def archive_all(urls: list[str]) -> list[dict]:
    results = []
    total = len(urls)

    print(f"Starting archive of {total} URL(s)...\n")

    for i, url in enumerate(urls, start=1):
        print(f"[{i}/{total}] Submitting: {url}")
        result = save_url(url)
        result["timestamp"] = datetime.utcnow().isoformat()
        results.append(result)

        if result["status"] == "success":
            print(f"  ✓ Archived → {result['archived_url']}")
        else:
            print(f"  ✗ {result.get('reason') or result.get('http_code')}")

        if i < total:
            time.sleep(DELAY_SECONDS)

    return results


def save_log(results: list[dict], path: str) -> None:
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nLog saved to {path}")


def print_summary(results: list[dict]) -> None:
    success = sum(1 for r in results if r["status"] == "success")
    failed = len(results) - success
    print(f"\n── Summary ──────────────────────")
    print(f"  Total   : {len(results)}")
    print(f"  Success : {success}")
    print(f"  Failed  : {failed}")
    print(f"─────────────────────────────────")


if __name__ == "__main__":
    results = archive_all(URLS)
    print_summary(results)
    save_log(results, LOG_FILE)
