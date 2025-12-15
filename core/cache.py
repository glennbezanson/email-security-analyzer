"""
SQLite Cache for API Responses
Reduces API calls and improves performance
"""

import sqlite3
import json
import hashlib
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class CacheManager:
    """
    SQLite-based cache for API responses

    Features:
    - Automatic TTL expiration
    - JSON serialization for complex objects
    - Thread-safe connections
    - Automatic cleanup of expired entries
    """

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        default_ttl_minutes: int = 15
    ):
        """
        Initialize cache manager

        Args:
            cache_dir: Directory for cache database. Defaults to ~/.cache/email-security-analyzer/
            default_ttl_minutes: Default time-to-live for cache entries
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".cache" / "email-security-analyzer"

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.cache_dir / "cache.db"
        self.default_ttl = timedelta(minutes=default_ttl_minutes)

        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    category TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_category ON cache(category)
            """)
            conn.commit()

    @contextmanager
    def _get_connection(self):
        """Get thread-safe database connection"""
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _make_key(self, key: str, **kwargs) -> str:
        """Generate cache key from base key and parameters"""
        if kwargs:
            param_str = json.dumps(kwargs, sort_keys=True)
            key = f"{key}:{hashlib.md5(param_str.encode()).hexdigest()}"
        return key

    def get(self, key: str, **kwargs) -> Optional[Any]:
        """
        Get cached value

        Args:
            key: Cache key
            **kwargs: Additional parameters to include in key hash

        Returns:
            Cached value or None if not found/expired
        """
        cache_key = self._make_key(key, **kwargs)

        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?",
                (cache_key,)
            )
            row = cursor.fetchone()

            if row:
                expires_at = datetime.fromisoformat(row['expires_at'])
                if datetime.utcnow() < expires_at:
                    try:
                        return json.loads(row['value'])
                    except json.JSONDecodeError:
                        return row['value']
                else:
                    # Entry expired, delete it
                    conn.execute("DELETE FROM cache WHERE key = ?", (cache_key,))
                    conn.commit()

        return None

    def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[timedelta] = None,
        category: Optional[str] = None,
        **kwargs
    ) -> None:
        """
        Set cached value

        Args:
            key: Cache key
            value: Value to cache (will be JSON serialized)
            ttl: Time-to-live. Defaults to default_ttl
            category: Optional category for bulk operations
            **kwargs: Additional parameters to include in key hash
        """
        cache_key = self._make_key(key, **kwargs)
        ttl = ttl or self.default_ttl

        now = datetime.utcnow()
        expires_at = now + ttl

        # Serialize value
        try:
            value_str = json.dumps(value, default=str)
        except (TypeError, ValueError):
            value_str = str(value)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO cache (key, value, created_at, expires_at, category)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    cache_key,
                    value_str,
                    now.isoformat(),
                    expires_at.isoformat(),
                    category
                )
            )
            conn.commit()

    def delete(self, key: str, **kwargs) -> bool:
        """
        Delete cached value

        Args:
            key: Cache key
            **kwargs: Additional parameters to include in key hash

        Returns:
            True if entry was deleted
        """
        cache_key = self._make_key(key, **kwargs)

        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM cache WHERE key = ?", (cache_key,))
            conn.commit()
            return cursor.rowcount > 0

    def clear_category(self, category: str) -> int:
        """
        Clear all entries in a category

        Args:
            category: Category to clear

        Returns:
            Number of entries deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE category = ?",
                (category,)
            )
            conn.commit()
            return cursor.rowcount

    def clear_expired(self) -> int:
        """
        Remove all expired entries

        Returns:
            Number of entries deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE expires_at < ?",
                (datetime.utcnow().isoformat(),)
            )
            conn.commit()
            return cursor.rowcount

    def clear_all(self) -> int:
        """
        Clear entire cache

        Returns:
            Number of entries deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM cache")
            conn.commit()
            return cursor.rowcount

    def get_stats(self) -> dict:
        """
        Get cache statistics

        Returns:
            Dictionary with cache stats
        """
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE expires_at < ?",
                (datetime.utcnow().isoformat(),)
            ).fetchone()[0]

            categories = {}
            for row in conn.execute(
                "SELECT category, COUNT(*) as count FROM cache GROUP BY category"
            ):
                categories[row['category'] or 'uncategorized'] = row['count']

            # Get database file size
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0

        return {
            'total_entries': total,
            'expired_entries': expired,
            'valid_entries': total - expired,
            'categories': categories,
            'database_size_bytes': db_size,
            'database_path': str(self.db_path)
        }

    def __repr__(self) -> str:
        stats = self.get_stats()
        return f"CacheManager(entries={stats['valid_entries']}, path={self.db_path})"
