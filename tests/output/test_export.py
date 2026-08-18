from __future__ import annotations

import io
import zipfile

import pytest
from link2vault.output.export import export_vault


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_export_stream_contains_only_relative_vault_files(tmp_path) -> None:
    vault = tmp_path / "vault-root"
    note = vault / "2026" / "08" / "note.md"
    note.parent.mkdir(parents=True)
    note.write_text("synthetic note\n", encoding="utf-8")

    response = export_vault(vault)
    content = b"".join([chunk async for chunk in response.body_iterator])

    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.namelist() == ["2026/08/note.md"]
        assert archive.read("2026/08/note.md") == b"synthetic note\n"
    assert not list(tmp_path.rglob("*.partial"))


def test_export_rejects_symlink_traversal(tmp_path) -> None:
    vault = tmp_path / "vault-root"
    vault.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("must not export", encoding="utf-8")
    (vault / "linked.txt").symlink_to(outside)

    with pytest.raises(ValueError, match="symlink"):
        export_vault(vault)
