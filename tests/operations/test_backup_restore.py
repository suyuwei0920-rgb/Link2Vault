from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKUP = ROOT / "scripts" / "backup.sh"
RESTORE = ROOT / "scripts" / "restore.sh"


def test_backup_and_restore_preserve_database_and_vault_without_overwrite(
    tmp_path,
) -> None:
    data_dir = tmp_path / "state"
    vault = tmp_path / "vault-root"
    destination = tmp_path / "backups"
    data_dir.mkdir()
    vault.mkdir()
    destination.mkdir()
    database = sqlite3.connect(data_dir / "link2vault.sqlite3")
    database.execute("CREATE TABLE sample (value TEXT)")
    database.execute("INSERT INTO sample VALUES ('synthetic')")
    database.commit()
    database.close()
    (vault / "note.md").write_text("synthetic note\n", encoding="utf-8")

    backed_up = subprocess.run(
        [
            "bash",
            str(BACKUP),
            "--data-dir",
            str(data_dir),
            "--vault",
            str(vault),
            "--destination",
            str(destination),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    backup_dir = Path(backed_up.stdout.strip())
    restored_data = tmp_path / "restored-state"
    restored_vault = tmp_path / "restored-vault"
    restored = subprocess.run(
        [
            "bash",
            str(RESTORE),
            "--backup",
            str(backup_dir),
            "--data-dir",
            str(restored_data),
            "--vault",
            str(restored_vault),
            "--confirm-restore",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    connection = sqlite3.connect(restored_data / "link2vault.sqlite3")
    value = connection.execute("SELECT value FROM sample").fetchone()[0]
    connection.close()
    assert backed_up.returncode == 0, backed_up.stderr
    assert restored.returncode == 0, restored.stderr
    assert value == "synthetic"
    assert (restored_vault / "note.md").read_text() == "synthetic note\n"

    repeated = subprocess.run(
        [
            "bash",
            str(RESTORE),
            "--backup",
            str(backup_dir),
            "--data-dir",
            str(restored_data),
            "--vault",
            str(restored_vault),
            "--confirm-restore",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert repeated.returncode != 0
