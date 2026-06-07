from datetime import datetime
import requests
from dotenv import load_dotenv
import os
from calendar import monthrange
from .cache import get_cache, save_cache

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def build_month_range(year: int, month: int) -> str:
    last_day = monthrange(year, month)[1]
    return f"{year}-{month:02d}-01..{year}-{month:02d}-{last_day:02d}"


def consult(ecosystem, n, year, month, severity):
    if not GITHUB_TOKEN:
        return {"status": 500, "message": "GitHub token not configured", "data": []}
    
    cache_key = f"{ecosystem}:{year}:{month}:{n}"

    cached = get_cache(cache_key)

    if cached:
        return {"status": 200, "message": "", "data": cached}

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2026-03-10",
    }

    now = datetime.now()
    year = year or now.year
    month = month or now.month

    params = {
        "ecosystem": ecosystem,
        "published": build_month_range(year, month),
        "severity": severity,
        "sort": "published",
        "direction": "desc",
        "per_page": n,
    }

    response = requests.get(
        "https://api.github.com/advisories", headers=headers, params=params
    )

    data = response.json()

    if response.status_code != 200:
        return {
            "status": response.status_code,
            "message": data.get("message", "Unknown error"),
            "data": [],
        }

    save_cache(cache_key, data)
    
    return {"status": 200, "message": "", "data": data}


def format_data(result):
    if result["status"] != 200:
        return result

    rows = []

    for advisory in result["data"]:
        cvss = advisory.get("cvss_severities", {})
        epss = advisory.get("epss", {})
        cwes = advisory.get("cwes", [])
        cvss3 = cvss.get("cvss_v3", {})
        cvss4 = cvss.get("cvss_v4", {})

        for vuln in advisory.get("vulnerabilities", []):
            package = vuln.get("package", {})
            cwe_ids = ", ".join(
                cwe.get("cwe_id", "") for cwe in cwes if cwe.get("cwe_id")
            )

            rows.append(
                {
                    "package": package.get("name"),
                    "severity": advisory.get("severity"),
                    "score": (
                        cvss4.get("score")
                        if cvss4.get("score", 0) > 0
                        else cvss3.get("score")
                    ),
                    "epss": round(epss.get("percentage", 0) * 100, 2),
                    "affected_versions": vuln.get("vulnerable_version_range"),
                    "fixed_version": vuln.get("first_patched_version"),
                    "published": advisory.get("published_at"),
                    "cve_id": advisory.get("cve_id"),
                    "cwe_id": cwe_ids,
                    "ghsa_id": advisory.get("ghsa_id"),
                    "summary": advisory.get("summary"),
                }
            )

    return {
        "status": 200,
        "message": "",
        "data": rows,
    }


def search_for_ecosystem(ecosystem, n = 5, year = None, month =  None, severity = None):
    if n > 50:
        return {
            "status": 400,
            "message": "Maximum 50 records can be displayed on console",
            "data": [],
        }

    data = consult(ecosystem, n, year, month, severity)
    data_clean = format_data(data)

    if data_clean["status"] != 200:
        return data_clean

    data_clean["data"] = data_clean["data"][:n]  # rows showed
    return data_clean
