from unittest.mock import patch, Mock
from lastvuln_cli.client import search_for_ecosystem, search_for_package


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_success(mock_get, git_advisory_data):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [git_advisory_data]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2026, 6)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 1

    row = result["data"][0]

    assert row["ghsa_id"] == "GHSA-q3w6-q3hc-c5x6"
    assert row["cve_id"] == "CVE-2026-47717"
    assert row["package"] == "fuxa-server"
    assert row["severity"] == "high"
    assert row["score"] == 8.9
    assert row["epss"] == 25.0
    assert row["fixed_version"] == "1.3.1"
    assert row["cwe_id"] == "CWE-201, CWE-202"


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_http_error(mock_get):
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.json.return_value = {"message": "Bad credentials"}

    mock_get.return_value = mock_response

    result = search_for_ecosystem("pip", 1, 2024, 5)

    assert result["status"] == 401
    assert result["message"] == "Bad credentials"
    assert result["data"] == []


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_cvss_version_priority(mock_get, git_advisory_data):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [git_advisory_data]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2026, 6)

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
    assert row["cwe_id"] == "CWE-201, CWE-202"


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_various_cwe(mock_get, git_advisory_data):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [git_advisory_data]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2026, 6)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 1

    row = result["data"][0]

    assert row["cwe_id"] == "CWE-201, CWE-202"


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_various_vulnerabilities(mock_get, git_advisory_data):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [git_advisory_data]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 2, 2026, 6)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 2
    assert result["data"][0]["package"] == "fuxa-server"
    assert result["data"][1]["package"] == "bugsink"


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_no_vulnerabilities(mock_get):
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

    result = search_for_ecosystem("npm", 2, 2025, 1)

    assert result["status"] == 200
    assert result["message"] == ""
    assert result["data"] == []


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_without_parameters(mock_get, git_advisory_data):
    mock_response = Mock()
    mock_response.status_code = 200

    mock_response.json.return_value = [git_advisory_data]

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm")

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 2


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_error_without_message(mock_get):
    mock_response = Mock()
    mock_response.status_code = 500

    mock_response.json.return_value = {}

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2025, 7)

    assert result["status"] == 500
    assert result["message"] == "Unknown error"
    assert result["data"] == []


@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_json_malformed(mock_get):
    mock_response = Mock()
    mock_response.status_code = 400

    mock_response.json.side_effect = ValueError("JSON invalid")

    mock_get.return_value = mock_response

    result = search_for_ecosystem("npm", 1, 2025, 7)

    assert result["status"] == 500
    assert result["message"] == "Invalid JSON response"
    assert result["data"] == []


@patch("lastvuln_cli.client.requests.post")
@patch("lastvuln_cli.client.requests.get")
def test_search_for_package_success(mock_get, mock_post):
    # OSV response
    mock_post_response = Mock()
    mock_post_response.status_code = 200
    mock_post_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-cpwx-vrp4-4pq7",
            }
        ]
    }
    mock_post.return_value = mock_post_response

    # GitHub Advisories response
    mock_get_response = Mock()
    mock_get_response.status_code = 200
    mock_get_response.json.return_value = [
        {
            "ghsa_id": "GHSA-cpwx-vrp4-4pq7",
            "cve_id": "CVE-2025-27516",
            "severity": "medium",
            "summary": "Jinja2 vulnerable to sandbox breakout through attr filter selecting format method",
            "published_at": "2025-03-05T20:40:14Z",
            "epss": {
                "percentage": 0.46,
            },
            "cvss_severities": {
                "cvss_v3": {
                    "score": 5.4,
                },
                "cvss_v4": {
                    "score": 0.0,
                },
            },
            "cwes": [
                {
                    "cwe_id": "CWE-1336",
                }
            ],
            "vulnerabilities": [
                {
                    "package": {
                        "name": "jinja2",
                    },
                    "vulnerable_version_range": "< 3.1.6",
                    "first_patched_version": "3.1.6",
                }
            ],
        }
    ]
    mock_get.return_value = mock_get_response

    result = search_for_package("3.1.4", "jinja2", "pip", 1)

    assert result["status"] == 200
    assert result["message"] == ""
    assert len(result["data"]) == 1

    row = result["data"][0]

    assert row["package"] == "jinja2"
    assert row["severity"] == "medium"
    assert row["score"] == 5.4
    assert row["epss"] == 46.0
    assert row["affected_versions"] == "< 3.1.6"
    assert row["fixed_version"] == "3.1.6"
    assert row["cve_id"] == "CVE-2025-27516"
    assert row["cwe_id"] == "CWE-1336"
    assert row["ghsa_id"] == "GHSA-cpwx-vrp4-4pq7"

    mock_post.assert_called_once()
    assert mock_get.call_count == 1


@patch("lastvuln_cli.client.requests.post")
def test_search_for_package_no_vulnerabilities(mock_post):
    mock_post_response = Mock()
    mock_post_response.status_code = 200
    mock_post_response.json.return_value = {"vulns": []}

    mock_post.return_value = mock_post_response
    result = search_for_package("4.1.0", "jinja2", "pip", 1)

    assert result["status"] == 200
    assert result["message"] == ""
    assert result["data"] == []


@patch("lastvuln_cli.client.requests.post")
@patch("lastvuln_cli.client.requests.get")
def test_search_for_package_git_error(mock_get, mock_post):
    # OSV response
    mock_post_response = Mock()
    mock_post_response.status_code = 200
    mock_post_response.json.return_value = {
        "vulns": [
            {
                "id": "GHSA-cpwx-vrp4-4pq7",
            }
        ]
    }
    mock_post.return_value = mock_post_response

    # GitHub Advisories response
    mock_get_response = Mock()
    mock_get_response.status_code = 500
    mock_get_response.json.return_value = {
        "message": "No advisories could be retrieved"
    }

    mock_get.return_value = mock_get_response
    result = search_for_package("3.1.4", "jinja2", "pip", 5)

    assert result["status"] == 500
    assert "advisories could be retrieved" in result["message"].lower()

    mock_post.assert_called_once()
    assert mock_get.call_count == 1


@patch("lastvuln_cli.client.requests.post")
def test_search_for_package_osv_error(mock_post):
    mock_post_response = Mock()
    mock_post_response.status_code = 500
    mock_post_response.json.return_value = {"message": "Internal Server Error"}

    mock_post.return_value = mock_post_response

    result = search_for_package("3.1.4", "jinja2", "pip")

    assert result["status"] == 500
    assert "internal server error" in result["message"].lower()

    mock_post.assert_called_once()


def test_token_not_configured(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)

    result = search_for_ecosystem("npm", 1, 2026, 6)

    assert result["status"] == 500
    assert result["message"] == "GitHub token not configured"
    assert result["data"] == []
