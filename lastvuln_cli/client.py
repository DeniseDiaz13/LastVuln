from datetime import datetime
import requests
from dotenv import load_dotenv
import os
from calendar import monthrange
from typing import Any
from .cache import get_cache, save_cache, cache_is_expired

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")


def build_month_range(year: int, month: int) -> str:
    last_day = monthrange(year, month)[1]
    return f"{year}-{month:02d}-01..{year}-{month:02d}-{last_day:02d}"


def consult_per_ecosystem(ecosystem: str, n: int, year: int | None, month: int | None, severity: str | None) -> dict[str, Any]:
    if not GITHUB_TOKEN:
        return {"status": 500, "message": "GitHub token not configured", "data": []}

    cache_key = f"{ecosystem}:{year}:{month}:{n}:{severity}"

    cached = get_cache(cache_key)
    expired = cache_is_expired(cached)

    if cached and not expired:
        return {"status": 200, "message": "", "data": cached["data"]}

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


def consult_per_package(ids: list[str], ecosystem: str, package: str, version: str, n: int) -> dict[str, Any]:
    if not GITHUB_TOKEN:
        return {"status": 500, "message": "GitHub token not configured", "data": []}
    
    cache_key = f"{ecosystem}:{package}:{version}:{n}"
    
    cached = get_cache(cache_key)
    expired = cache_is_expired(cached)

    if cached and not expired:
        return {"status": 200, "message": "", "data": cached["data"]}

    data: list[dict[str, Any]] = [] 
    for i in ids:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "X-GitHub-Api-Version": "2026-03-10",
        }

        params = {
            "ghsa_id": i,
            "sort": "published",
            "direction": "desc",
        }

        response = requests.get(
            "https://api.github.com/advisories", headers=headers, params=params
        )
        
        if response.status_code != 200:
            return {
                "status": response.status_code,
                "message": response.json().get("message", "Unknown error"),
                "data": [],
            }
        
        data.extend(response.json())
        
    save_cache(cache_key, data)
    
    return {"status": 200, "message": "", "data": data}


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
        "swift": "SwiftURL" 
    }

    return map.get(ecosystem)


def search_for_package(version: str, name_pkg: str, ecosystem: str, n: int = 5) -> dict[str, Any]:
    if n > 50:
        return {
            "status": 400,
            "message": "Maximum 50 records can be displayed on console",
            "data": [],
        }
    
    ecosystem_n = ecosystem_mapping(ecosystem)
    
    payload = {
        "version": version,
        "package": {
            "name": name_pkg,
            "ecosystem": ecosystem_n,
        }
    }

    response = requests.post("https://api.osv.dev/v1/query", json=payload)
    res = response.json()

    ids = [item.get("id") for item in res.get("vulns", [])] 
    data = consult_per_package(ids, ecosystem, name_pkg, version, n)
    data_clean = format_data(data)
    
    if data_clean["status"] != 200:
        return data_clean
     
    data_clean["data"] = data_clean["data"][:n]  # rows showed
    return data_clean


def search_for_ecosystem(ecosystem: str, n: int = 5, year: int | None = None, month: int | None = None, severity: str | None = None) -> dict[str, Any]:
    if n > 50:
        return {
            "status": 400,
            "message": "Maximum 50 records can be displayed on console",
            "data": [],
        }

    data = consult_per_ecosystem(ecosystem, n, year, month, severity)
    data_clean = format_data(data)

    if data_clean["status"] != 200:
        return data_clean

    data_clean["data"] = data_clean["data"][:n]  # rows showed
    return data_clean
