from __future__ import annotations

import json
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "clients" / "ios" / "shortcut-manifest.json"
inspect_shortcut = runpy.run_path(str(ROOT / "scripts" / "inspect_shortcut.py"))[
    "inspect_shortcut"
]


def test_ios_manifest_is_secret_free_and_uses_enrollment_flow() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    assert manifest["setup_inputs"] == ["server_base_url", "one_time_code"]
    assert manifest["accepts"] == ["text", "url"]
    assert manifest["enroll_path"] == "/ingest/enroll"
    assert manifest["capture_path"] == "/ingest/links"
    assert "default_server" not in manifest
    assert "device_token" not in manifest

    audit = inspect_shortcut(MANIFEST)
    assert audit.safe is True
    assert audit.findings == ()
