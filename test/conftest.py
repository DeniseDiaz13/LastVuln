import pytest
import sqlite3
from unittest.mock import patch
from lastvuln_cli.cache import DB_NAME, init_db

@pytest.fixture(autouse = True)
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
