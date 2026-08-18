"""SQLite connection configuration and schema initialization."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path


class Database:
    """Own one correctly configured SQLite connection."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "link2vault.sqlite3"
        self.connection = sqlite3.connect(
            self.path,
            isolation_level=None,
            timeout=5.0,
            check_same_thread=False,
        )
        self.lock = threading.RLock()
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.execute("PRAGMA synchronous = NORMAL")
        schema_path = Path(__file__).with_name("schema.sql")
        self.connection.executescript(schema_path.read_text(encoding="utf-8"))
        columns = {
            row["name"]
            for row in self.connection.execute("PRAGMA table_info(capture_tasks)")
        }
        if "input_ref" not in columns:
            self.connection.execute("ALTER TABLE capture_tasks ADD COLUMN input_ref TEXT")

    def close(self) -> None:
        """Close the underlying connection."""

        self.connection.close()
