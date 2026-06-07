import json
import sqlite3
from datetime import datetime

DB_NAME = "cache.db"


def init_db():
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


def save_cache(key, data):
    conn = sqlite3.connect(DB_NAME)

    conn.execute(
        """
        INSERT OR REPLACE INTO advisories_cache
        (cache_key, response_json, created_at)
        VALUES (?, ?, ?)
        """,
        (key, json.dumps(data), datetime.now()),
    )

    conn.commit()
    conn.close()


def get_cache(key):
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.execute(
        """
        SELECT response_json
        FROM advisories_cache
        WHERE cache_key = ?
        """,
        (key,),
    )

    row = cursor.fetchone()

    conn.close()

    if not row:
        return None

    return json.loads(row[0])
