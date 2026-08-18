from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "sync_vault_rsync.sh"


def fake_rsync(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    capture = tmp_path / "rsync-args"
    executable = binary_dir / "rsync"
    executable.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$@" > "$SYNC_CAPTURE"\n',
        encoding="utf-8",
    )
    executable.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = f"{binary_dir}:{environment['PATH']}"
    environment["SYNC_CAPTURE"] = str(capture)
    return capture, environment


def test_dry_run_preserves_history_and_uses_partial_directory(tmp_path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    capture, environment = fake_rsync(tmp_path)

    completed = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--source",
            str(source),
            "--destination",
            str(destination),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )

    arguments = capture.read_text(encoding="utf-8").splitlines()
    assert completed.returncode == 0, completed.stderr
    assert "--dry-run" in arguments
    assert "--partial-dir=.partial" in arguments
    assert not any(argument == "--delete" for argument in arguments)
    assert arguments[-2:] == [f"{source}/", f"{destination}/"]


def test_rejects_root_symlink_and_unresolved_destination(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    real_destination = tmp_path / "real"
    real_destination.mkdir()
    symlink = tmp_path / "linked"
    symlink.symlink_to(real_destination, target_is_directory=True)

    for destination in ("/", str(symlink), "$UNRESOLVED/path"):
        completed = subprocess.run(
            [
                "bash",
                str(SCRIPT),
                "--source",
                str(source),
                "--destination",
                destination,
                "--dry-run",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode != 0


def test_lock_prevents_overlapping_sync(tmp_path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    lock = Path(f"{destination}.link2vault-sync.lock")
    lock.mkdir()

    completed = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--source",
            str(source),
            "--destination",
            str(destination),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "already running" in completed.stderr
