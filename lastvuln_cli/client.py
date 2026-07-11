from datetime import datetime
import requests
from dotenv import load_dotenv
import os
from calendar import monthrange
from typing import Any
from .cache import get_cache, save_cache, cache_is_expired
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()


def build_month_range(year: int, month: int) -> str:
    last_day = monthrange(year, month)[1]
    return f"{year}-{month:02d}-01..{year}-{month:02d}-{last_day:02d}"


def parse_json(response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {
            "status": 500,
            "message": "Invalid JSON response",
            "data": [],
        }

    if response.status_code != 200:
        return {
            "status": response.status_code,
            "message": (
                data.get("message", "Unknown error")
                if isinstance(data, dict)
                else "Unknown error"
            ),
            "data": [],
        }

    if isinstance(data, list):
        return {
            "status": 200,
            "message": "",
            "data": data,
        }

    return {
        "status": 500,
        "message": "Unexpected response format",
        "data": [],
    }


def consult_per_ecosystem(
    ecosystem: str, n: int, year: int | None, month: int | None, severity: str | None
) -> dict[str, Any]:
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

    if not GITHUB_TOKEN:
        return {"status": 500, "message": "GitHub token not configured", "data": []}

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
        "https://api.github.com/advisories",
        headers=headers,
        params=params,
        timeout=10,
    )

    try:
        response = requests.get(
            "https://api.github.com/advisories",
            headers=headers,
            params=params,
            timeout=10,
        )
    except requests.RequestException as e:
        return {
            "status": 500,
            "message": str(e),
            "data": [],
        }

    return parse_json(response)


def fetch_advisory(ghsa_id: str, headers: dict[str, str]) -> dict[str, Any]:
    params = {
        "ghsa_id": ghsa_id,
        "sort": "published",
        "direction": "desc",
    }

    try:
        response = requests.get(
            "https://api.github.com/advisories",
            headers=headers,
            params=params,
            timeout=10,
        )
    except requests.RequestException as e:
        return {
            "status": 500,
            "message": str(e),
            "data": [],
        }

    if response.status_code != 200:
        try:
            message = response.json().get("message", "Unknown error")
        except ValueError:
            message = "Invalid JSON response"

        return {
            "status": response.status_code,
            "message": message,
            "data": [],
        }

    return {
        "status": 200,
        "message": "",
        "data": response.json(),
    }


def consult_per_package(ids: list[str]) -> dict[str, Any]:
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

    if not GITHUB_TOKEN:
        return {
            "status": 500,
            "message": "GitHub token not configured",
            "data": [],
        }

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2026-03-10",
    }

    data = []
    errors = []
    with ThreadPoolExecutor(max_workers = 5) as executor:
        futures = [
            executor.submit(fetch_advisory, ghsa_id, headers)
            for ghsa_id in ids
        ]

        for future in as_completed(futures):
            result = future.result()

            if result["status"] == 200:
                data.extend(result["data"])
            else:
                errors.append(result)

    return {
        "status": 200 if data else 500,
        "message": "" if data else "No advisories could be retrieved",
        "data": data,
        "errors": errors,
    }


def format_data(result: dict[str, Any]) -> dict[str, Any]:
    if result["status"] != 200:
        return result

    rows: list[dict[str, Any]] = []

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

            try:
                cvss4_score = float(cvss4.get("score", 0))
            except (TypeError, ValueError):
                cvss4_score = 0

            rows.append(
                {
                    "package": package.get("name"),
                    "severity": advisory.get("severity"),
                    "score": (
                        cvss4.get("score") if cvss4_score > 0 else cvss3.get("score")
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


def ecosystem_mapping(ecosystem: str):
    map = {
        "rubygems": "RubyGems",
        "npm": "npm",
        "pip": "PyPI",
        "maven": "Maven",
        "nuget": "NuGet",
        "composer": "Packagist",
        "go": "Go",
        "rust": "crates.io",
        "erlang": "Hex",
        "pub": "Pub",
        "swift": "SwiftURL",
    }

    return map.get(ecosystem)


def fetch_ghsa_ids(version: str, package: str, ecosystem: str) -> dict[str, Any]:
    ecosystem_n = ecosystem_mapping(ecosystem)
    if not ecosystem_n:
        return {
            "status": 400,
            "message": "Invalid ecosystem",
            "data": [],
        }

    payload = {
        "version": version,
        "package": {
            "name": package,
            "ecosystem": ecosystem_n,
        },
    }

    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=10,
        )
    except requests.RequestException as e:
        return {
            "status": 500,
            "message": str(e),
            "data": [],
        }

    res: dict[str, Any] = {}
    try:
        res = response.json()
    except ValueError:
        return {
            "status": 500,
            "message": "Invalid JSON response",
            "data": [],
        }

    if response.status_code != 200:
        return {
            "status": response.status_code,
            "message": res.get("message", "Unknown error"),
            "data": [],
        }

    ids = []
    seen = set()
    for vuln in res.get("vulns", []):
        candidates = [
            vuln.get("id"),
            *vuln.get("aliases", []),
        ]  # OSV advisories may use non-GHSA IDs (PYSEC, GO, RUSTSEC, etc.), so also inspect aliases.

        for candidate in candidates:
            if candidate and candidate.startswith("GHSA-") and candidate not in seen:
                seen.add(candidate)
                ids.append(candidate)

    return {
        "status": 200,
        "message": "",
        "data": ids,
    }


def search_for_package(
    version: str, package: str, ecosystem: str, n: int = 10
) -> dict[str, Any]:
    if n < 1 or n > 50:
        return {
            "status": 400,
            "message": "Records limit must be between 1 and 50",
            "data": [],
        }

    cache_key = f"{ecosystem}:{package}:{version}:{n}"
    cached = get_cache(cache_key)

    if cached and not cache_is_expired(cached):
        return {"status": 200, "message": "", "data": cached["data"]}

    res = fetch_ghsa_ids(version, package, ecosystem)

    if res["status"] != 200:
        return res

    if not res["data"]:
        return {
            "status": 200,
            "message": "",
            "data": [],
        }

    data = consult_per_package(res["data"])
    data_clean = format_data(data)

    if data_clean["status"] != 200:
        return data_clean

    data_clean["data"] = data_clean["data"][:n]  # rows showed
    save_cache(cache_key, data_clean["data"])

    return data_clean


def search_for_ecosystem(
    ecosystem: str,
    n: int = 10,
    year: int | None = None,
    month: int | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    if n < 1 or n > 50:
        return {
            "status": 400,
            "message": "Records limit must be between 1 and 50",
            "data": [],
        }

    cache_key = f"{ecosystem}:{year}:{month}:{n}:{severity}"
    cached = get_cache(cache_key)

    if cached and not cache_is_expired(cached):
        return {"status": 200, "message": "", "data": cached["data"]}

    data = consult_per_ecosystem(ecosystem, n, year, month, severity)
    data_clean = format_data(data)

    if data_clean["status"] != 200:
        return data_clean

    data_clean["data"] = data_clean["data"][:n]  # rows showed
    save_cache(cache_key, data_clean["data"])

    return data_clean
