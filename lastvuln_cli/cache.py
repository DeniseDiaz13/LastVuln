import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

DB_NAME = "cache.db"
CACHE_TTL = 24  # hours


def init_db() -> None:
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS advisories_cache (
            cache_key TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def save_cache(key: str, data: dict[str, Any] | list[dict[str, Any]]) -> None:
    conn = sqlite3.connect(DB_NAME)

    conn.execute(
        """
        INSERT OR REPLACE INTO advisories_cache
        (
            cache_key, 
            response_json, 
            created_at
        )
        VALUES 
        (
            ?, 
            ?, 
            ?
        )
        """,
        (key, json.dumps(data), datetime.now().isoformat()),
    )

    conn.commit()
    conn.close()


def get_cache(key: str) -> dict | None:
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.execute(
        """
        SELECT
            cache_key,
            response_json,
            created_at
        FROM advisories_cache
        WHERE 
            cache_key = ?
        """,
        (key,),
    )

    row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    return {"cache_key": row[0], "data": json.loads(row[1]), "created_at": row[2]}


def delete_cache(key: str) -> bool:
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.execute(
        """
        DELETE FROM advisories_cache
        WHERE 
            cache_key = ?
        """,
        (key,),
    )

    conn.commit()

    deleted_rows = cursor.rowcount

    conn.close()

    return deleted_rows > 0


def cache_is_expired(cached: dict | None) -> bool:
    if cached is None:
        return True

    created_at = cached.get("created_at")

    if not created_at:
        return True

    created_at_datetime = datetime.fromisoformat(created_at)

    expired = (datetime.now() - created_at_datetime) > timedelta(hours=CACHE_TTL)

    if expired:
        delete_cache(cached["cache_key"])

    return expired
