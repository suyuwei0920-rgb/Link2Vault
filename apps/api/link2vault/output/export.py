"""Safe, deterministic vault ZIP export."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from fastapi.responses import StreamingResponse


def export_vault(vault_root: Path) -> StreamingResponse:
    """Return a ZIP stream without following symlinks or creating temp files."""

    root = vault_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("vault root must be a directory")
    files: list[tuple[Path, str]] = []
    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink():
            raise ValueError("vault export does not allow symlinks")
        if not candidate.is_file():
            continue
        resolved = candidate.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ValueError("vault export path escaped its root")
        files.append((resolved, resolved.relative_to(root).as_posix()))

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, relative in files:
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    payload = output.getvalue()
    return StreamingResponse(
        iter((payload,)),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="link2vault-export.zip"'},
    )
