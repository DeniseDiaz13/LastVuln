from unittest.mock import patch, Mock
from lastvuln_cli.client import search_for_ecosystem


@patch("lastvuln_cli.client.requests.get")
def test_search_success(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [
        {
            "ghsa_id": "GHSA-q3w6-q3hc-c5x6",
            "cve_id": "CVE-2026-47717",
            "severity": "high",
            "summary": "FUXA's Unauthenticated Project Data Disclosure Exposes Server-Side Scripts and Device Configurations",
            "published_at": "2023-04-27T22:51:18Z",
            "epss": {"percentage": 0.25},
            "cvss_severities": {
                "cvss_v3": {"score": 7.5},
                "cvss_v4": {"score": 0.0},
            },
            "cwes": [
                {
                    "cwe_id": "CWE-201",
                    "name": "Insertion of Sensitive Information Into Sent Data",
                }
            ],
            "vulnerabilities": [
                {
                    "package": {
                        "ecosystem": "npm",
                        "name": "fuxa-server",
                    },
                    "vulnerable_version_range": "=1.3.0",
                    "first_patched_version": "1.3.1",
                }
            ],
        }
    ]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2023, 4)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 1

    row = result["data"][0]

    assert row["ghsa_id"] == "GHSA-q3w6-q3hc-c5x6"
    assert row["cve_id"] == "CVE-2026-47717"
    assert row["package"] == "fuxa-server"
    assert row["severity"] == "high"
    assert row["score"] == 7.5
    assert row["epss"] == 25.0
    assert row["fixed_version"] == "1.3.1"
    assert row["cwe_id"] == "CWE-201"


@patch("lastvuln_cli.client.requests.get")
def test_search_http_error(mock_get):
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"message": "Bad credentials"}

    mock_get.return_value = mock_response

    result = search_for_ecosystem("pip", 1, 2024, 5)

    assert result["status"] == 401
    assert result["message"] == "Bad credentials"
    assert result["data"] == []


@patch("lastvuln_cli.client.requests.get")
def test_search_cvss_version_priority(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [
        {
            "ghsa_id": "GHSA-q3w6-q3hc-c5x6",
            "cve_id": "CVE-2026-47717",
            "severity": "high",
            "summary": "FUXA's Unauthenticated Project Data Disclosure Exposes Server-Side Scripts and Device Configurations",
            "published_at": "2024-05-27T22:51:18Z",
            "epss": {"percentage": 0.25},
            "cvss_severities": {
                "cvss_v3": {"score": 7.5},
                "cvss_v4": {"score": 8.9},
            },
            "cwes": [
                {
                    "cwe_id": "CWE-201",
                    "name": "Insertion of Sensitive Information Into Sent Data",
                }
            ],
            "vulnerabilities": [
                {
                    "package": {
                        "ecosystem": "npm",
                        "name": "fuxa-server",
                    },
                    "vulnerable_version_range": "=1.3.0",
                    "first_patched_version": "1.3.1",
                }
            ],
        }
    ]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2024, 5)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 1

    row = result["data"][0]

    assert row["ghsa_id"] == "GHSA-q3w6-q3hc-c5x6"
    assert row["cve_id"] == "CVE-2026-47717"
    assert row["package"] == "fuxa-server"
    assert row["severity"] == "high"
    assert row["score"] == 8.9  # cvss_v4 takes priority when available.
    assert row["epss"] == 25.0
    assert row["fixed_version"] == "1.3.1"
    assert row["cwe_id"] == "CWE-201"


@patch("lastvuln_cli.client.requests.get")
def test_search_various_cwe(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [
        {
            "ghsa_id": "GHSA-q3w6-q3hc-c5x6",
            "cve_id": "CVE-2026-47717",
            "severity": "high",
            "summary": "FUXA's Unauthenticated Project Data Disclosure Exposes Server-Side Scripts and Device Configurations",
            "published_at": "2025-06-17T22:51:18Z",
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
                }
            ],
        }
    ]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2025, 6)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 1

    row = result["data"][0]

    assert row["cwe_id"] == "CWE-201, CWE-202"


@patch("lastvuln_cli.client.requests.get")
def test_search_various_vulnerabilities(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [
        {
            "ghsa_id": "GHSA-q3w6-q3hc-c5x6",
            "cve_id": "CVE-2026-47717",
            "severity": "high",
            "summary": "FUXA's Unauthenticated Project Data Disclosure Exposes Server-Side Scripts and Device Configurations",
            "published_at": "2025-07-07T22:51:18Z",
            "epss": {"percentage": 0.2473},
            "cvss_severities": {
                "cvss_v3": {"score": 7.5},
                "cvss_v4": {"score": 8.9},
            },
            "cwes": [
                {
                    "cwe_id": "CWE-201",
                    "name": "Insertion of Sensitive Information Into Sent Data",
                }
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
    ]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 2, 2025, 7)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 2
    assert result["data"][0]["package"] == "fuxa-server"
    assert result["data"][1]["package"] == "bugsink"


@patch("lastvuln_cli.client.requests.get")
def test_search_no_vulnerabilities(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [
        {
            "ghsa_id": "GHSA-q3w6-q3hc-c5x6",
            "cve_id": "CVE-2026-47717",
            "severity": "high",
            "summary": "FUXA's Unauthenticated Project Data Disclosure Exposes Server-Side Scripts and Device Configurations",
            "published_at": "2025-07-07T22:51:18Z",
            "epss": {"percentage": 0.2473},
            "cvss_severities": {
                "cvss_v3": {"score": 7.5},
                "cvss_v4": {"score": 8.9},
            },
            "cwes": [
                {
                    "cwe_id": "CWE-201",
                    "name": "Insertion of Sensitive Information Into Sent Data",
                }
            ],
            "vulnerabilities": [],
        }
    ]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 2, 2025, 7)

    assert result["status"] == 200
    assert result["message"] == ""
    assert result["data"] == []


@patch("lastvuln_cli.client.requests.get")
def test_search_without_parameters(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [
        {
            "ghsa_id": "GHSA-q3w6-q3hc-c5x6",
            "cve_id": "CVE-2026-47717",
            "severity": "high",
            "summary": "FUXA's Unauthenticated Project Data Disclosure Exposes Server-Side Scripts and Device Configurations",
            "published_at": "2025-06-13T22:51:18Z",
            "epss": {"percentage": 0.2473},
            "cvss_severities": {
                "cvss_v3": {"score": 7.5},
                "cvss_v4": {"score": 8.9},
            },
            "cwes": [
                {
                    "cwe_id": "CWE-201",
                    "name": "Insertion of Sensitive Information Into Sent Data",
                }
            ],
            "vulnerabilities": [
                {
                    "package": {
                        "ecosystem": "npm",
                        "name": "fuxa-server",
                    },
                    "vulnerable_version_range": "=1.3.0",
                    "first_patched_version": "1.3.1",
                }
            ],
        }
    ]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm")

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 1


@patch("lastvuln_cli.client.requests.get")
def test_search_error_without_message(mock_get):
    mock_response = Mock()
    mock_response.status_code = 500

    mock_response.json.return_value = {}

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2025, 7)

    assert result["status"] == 500
    assert result["message"] == "Unknown error"
    assert result["data"] == []


@patch("lastvuln_cli.client.GITHUB_TOKEN", None)
def test_token_not_configured():
    result = search_for_ecosystem("pip", 1, 2024, 5)

    assert result["status"] == 500
    assert result["message"] == "GitHub token not configured"
    assert result["data"] == []

