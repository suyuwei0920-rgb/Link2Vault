"""SQLite repository for one-time enrollment and device identities."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import uuid4

from link2vault.domain.devices import DeviceIdentity
from link2vault.storage.database import Database


class DeviceRepository:
    """Persist only keyed credential digests, never plaintext credentials."""

    def __init__(self, data_dir: Path) -> None:
        self._database = Database(data_dir)
        self._connection = self._database.connection

    def close(self) -> None:
        """Release the repository connection."""

        self._database.close()

    def store_enrollment_code(
        self,
        *,
        name: str,
        code_digest: str,
        created_at: datetime,
        expires_at: datetime,
    ) -> None:
        """Store one HMAC digest for a pending enrollment."""

        self._connection.execute(
            """
            INSERT INTO enrollment_codes (
                code_digest, device_name, created_at, expires_at, used_at
            ) VALUES (?, ?, ?, ?, NULL)
            """,
            (code_digest, name, created_at.isoformat(), expires_at.isoformat()),
        )

    def exchange_code(
        self,
        *,
        code_digest: str,
        token_digest: str,
        now: datetime,
    ) -> DeviceIdentity | None:
        """Atomically consume a code and create its device."""

        with self._database.lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT device_name FROM enrollment_codes
                    WHERE code_digest = ? AND used_at IS NULL AND expires_at >= ?
                    """,
                    (code_digest, now.isoformat()),
                ).fetchone()
                if row is None:
                    self._connection.execute("COMMIT")
                    return None
                device_id = str(uuid4())
                timestamp = now.isoformat()
                self._connection.execute(
                    "UPDATE enrollment_codes SET used_at = ? WHERE code_digest = ?",
                    (timestamp, code_digest),
                )
                self._connection.execute(
                    """
                    INSERT INTO devices (
                        id, name, token_digest, created_at, last_used_at, revoked_at
                    ) VALUES (?, ?, ?, ?, NULL, NULL)
                    """,
                    (device_id, row["device_name"], token_digest, timestamp),
                )
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        return self.get(device_id)

    def verify_token(self, digest: str, now: datetime) -> DeviceIdentity | None:
        """Return and touch one active device by token digest."""

        row = self._connection.execute(
            """
            SELECT id FROM devices
            WHERE token_digest = ? AND revoked_at IS NULL
            """,
            (digest,),
        ).fetchone()
        if row is None:
            return None
        self._connection.execute(
            "UPDATE devices SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL",
            (now.isoformat(), row["id"]),
        )
        return self.get(row["id"])

    def revoke(self, device_id: str, now: datetime) -> bool:
        """Mark one device revoked and report whether it existed."""

        cursor = self._connection.execute(
            """
            UPDATE devices SET revoked_at = ?
            WHERE id = ? AND revoked_at IS NULL
            """,
            (now.isoformat(), device_id),
        )
        return cursor.rowcount == 1

    def get(self, device_id: str) -> DeviceIdentity:
        """Load one device or raise ``KeyError``."""

        row = self._connection.execute(
            "SELECT * FROM devices WHERE id = ?",
            (device_id,),
        ).fetchone()
        if row is None:
            raise KeyError(device_id)
        return self._to_identity(row)

    def list_devices(self) -> tuple[DeviceIdentity, ...]:
        """List devices newest first without credential digests."""

        rows = self._connection.execute(
            "SELECT * FROM devices ORDER BY created_at DESC, id"
        ).fetchall()
        return tuple(self._to_identity(row) for row in rows)

    @staticmethod
    def _to_identity(row: object) -> DeviceIdentity:
        return DeviceIdentity(
            id=row["id"],
            name=row["name"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_used_at=(
                None
                if row["last_used_at"] is None
                else datetime.fromisoformat(row["last_used_at"])
            ),
            revoked_at=(
                None
                if row["revoked_at"] is None
                else datetime.fromisoformat(row["revoked_at"])
            ),
        )
