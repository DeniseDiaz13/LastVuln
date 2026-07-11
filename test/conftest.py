import pytest
import sqlite3
from unittest.mock import patch
from lastvuln_cli.cache import DB_NAME, init_db


@pytest.fixture(autouse=True)
def disable_cache():
    with patch("lastvuln_cli.client.get_cache", return_value=None):
        with patch("lastvuln_cli.client.cache_is_expired", return_value=True):
            with patch("lastvuln_cli.client.save_cache"):
                yield


@pytest.fixture
def clean_cache():
    init_db()

    conn = sqlite3.connect(DB_NAME)
    conn.execute("DELETE FROM advisories_cache")
    conn.commit()
    conn.close()

    yield


@pytest.fixture
def git_advisory_data():
    return {
        "ghsa_id": "GHSA-q3w6-q3hc-c5x6",
        "cve_id": "CVE-2026-47717",
        "severity": "high",
        "summary": "FUXA's Unauthenticated Project Data Disclosure Exposes Server-Side Scripts and Device Configurations",
        "published_at": "2026-06-13T22:51:18Z",
        "epss": {"percentage": 0.25},
        "cvss_severities": {
            "cvss_v3": {"score": 7.5},
            "cvss_v4": {"score": 8.9},
        },
        "cwes": [
            {
                "cwe_id": "CWE-201",
                "name": "Insertion of Sensitive Information Into Sent Data",
            },
            {
                "cwe_id": "CWE-202",
                "name": "Insertion of Sensitive Information Into Sent Data",
            },
        ],
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": "npm",
                    "name": "fuxa-server",
                },
                "vulnerable_version_range": "=1.3.0",
                "first_patched_version": "1.3.1",
            },
            {
                "package": {
                    "ecosystem": "npm",
                    "name": "bugsink",
                },
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": "2.1.0",
            },
        ],
    }


@pytest.fixture(autouse=True)
def mock_github_token(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "fake_token")
