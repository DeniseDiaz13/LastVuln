import pytest
from unittest.mock import patch


@pytest.fixture(autouse = True)
def disable_cache():
    print("CACHE DISABLED")
    with patch("lastvuln_cli.client.get_cache", return_value=None):
        with patch("lastvuln_cli.client.cache_is_expired", return_value=True):
            with patch("lastvuln_cli.client.save_cache"):
                yield
