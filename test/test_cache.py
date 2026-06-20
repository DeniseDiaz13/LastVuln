from lastvuln_cli.cache import delete_cache, save_cache, get_cache, cache_is_expired
from datetime import datetime, timedelta


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
