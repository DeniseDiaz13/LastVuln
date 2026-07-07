from lastvuln_cli.cache import delete_cache, save_cache, get_cache, cache_is_expired
from lastvuln_cli.client import search_for_ecosystem, search_for_package
from datetime import datetime, timedelta
from unittest.mock import patch


def test_save_and_get_cache(clean_cache):
    data = {"data": "test_json"}
    key = "test_key"

    save_cache(key, data)
    cached = get_cache(key)

    assert cached is not None
    assert cached["cache_key"] == key
    assert cached["data"] == data


def test_delete_cache(clean_cache):
    data = {"data": "test_json"}
    key = "test_key"

    save_cache(key, data)
    deleted = delete_cache(key)

    assert deleted is True
    assert get_cache(key) is None


def test_nonexistent_key_deleted(clean_cache):
    deleted = delete_cache("test_key")

    assert deleted is False


def test_nonexistent_key_get(clean_cache):
    result = get_cache("test_key")

    assert result is None


def test_cache_expired(clean_cache):
    cached = {
        "cache_key": "old",
        "created_at": (datetime.now() - timedelta(days=2)).isoformat(),
    }

    assert cache_is_expired(cached) is True


def test_cache_not_expired(clean_cache):
    cached = {
        "cache_key": "new",
        "created_at": datetime.now().isoformat(),
    }

    assert cache_is_expired(cached) is False


@patch("lastvuln_cli.client.cache_is_expired", return_value=False)
@patch("lastvuln_cli.client.get_cache")
@patch("lastvuln_cli.client.requests.post")
@patch("lastvuln_cli.client.requests.get")
def test_search_for_package_uses_cache(
    mock_get,
    mock_post,
    mock_get_cache,
    mock_cache_is_expired,
):
    cached_rows = [
        {
            "package": "jinja2",
            "severity": "medium",
            "score": 5.4,
            "epss": 46.0,
            "affected_versions": "< 3.1.6",
            "fixed_version": "3.1.6",
            "published": "2025-03-05T20:40:14Z",
            "cve_id": "CVE-2025-27516",
            "cwe_id": "CWE-1336",
            "ghsa_id": "GHSA-cpwx-vrp4-4pq7",
            "summary": "...",
        }
    ]

    mock_get_cache.return_value = {
        "cache_key": "pip:jinja2:3.1.4:1",
        "created_at": datetime.now().isoformat(),
        "data": cached_rows,
    }

    result = search_for_package("3.1.4", "jinja2", "pip", 1)

    assert result == {
        "status": 200,
        "message": "",
        "data": cached_rows,
    }

    mock_get_cache.assert_called_once()
    mock_cache_is_expired.assert_called_once()

    mock_post.assert_not_called()
    mock_get.assert_not_called()


@patch("lastvuln_cli.client.cache_is_expired", return_value=False)
@patch("lastvuln_cli.client.get_cache")
@patch("lastvuln_cli.client.requests.get")
def test_search_for_ecosystem_uses_cache(
    mock_get,
    mock_get_cache,
    mock_cache_is_expired,
):
    cached_rows = [
        {
            "package": "io.openremote:openremote-manager",
            "severity": "high",
            "score": 7.2,
            "epss": 0,
            "affected_versions": "< 1.26.0",
            "fixed_version": "1.26.0",
            "published": "2026-07-06T21:51:32Z",
            "cve_id": None,
            "cwe_id": "CWE-89",
            "ghsa_id": "GHSA-cgfv-jrfp-2r7v",
            "summary": "OpenRemote has Authenticated SQL Injection via Datapoint Crosstab Export",
        }
    ]

    mock_get_cache.return_value = {
        "cache_key": "maven:None:None:1:None",
        "created_at": datetime.now().isoformat(),
        "data": cached_rows,
    }

    result = search_for_ecosystem("maven", 1, None, None, None)

    assert result == {
        "status": 200,
        "message": "",
        "data": cached_rows,
    }

    mock_get_cache.assert_called_once()
    mock_cache_is_expired.assert_called_once()

    mock_get.assert_not_called()
