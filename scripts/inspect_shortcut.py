"""Audit the public iPhone Shortcut manifest for embedded private state."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_ENDPOINT = re.compile(r"https?://", re.IGNORECASE)
_SECRET = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{12,}|Bearer\s+[A-Za-z0-9._~-]{12,}|"
    r"device[_-]?token\s*[:=])",
    re.IGNORECASE,
)
_PRIVATE_PATH = re.compile(r"/(?:Users|home)/|[A-Za-z]:[/\\]Users[/\\]")


@dataclass(frozen=True)
class ShortcutAudit:
    safe: bool
    findings: tuple[str, ...]


def inspect_shortcut(path: Path) -> ShortcutAudit:
    """Validate structure and reject endpoints, tokens and private paths."""

    text = path.read_text(encoding="utf-8")
    findings: list[str] = []
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError:
        return ShortcutAudit(False, ("invalid_json",))
    required = {
        "schema_version",
        "name",
        "setup_inputs",
        "accepts",
        "enroll_path",
        "capture_path",
    }
    if not isinstance(manifest, dict) or not required.issubset(manifest):
        findings.append("invalid_structure")
    if _ENDPOINT.search(text):
        findings.append("embedded_endpoint")
    if _SECRET.search(text):
        findings.append("embedded_secret")
    if _PRIVATE_PATH.search(text):
        findings.append("private_path")
    return ShortcutAudit(not findings, tuple(findings))
