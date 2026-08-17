"""Audit the files eligible for inclusion in the public repository."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TEXT_LIMIT_BYTES = 2 * 1024 * 1024
CONFIG_FILE = ".public-allowlist"

MEDIA_EXTENSIONS = {
    ".aac",
    ".avi",
    ".flac",
    ".m4a",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".ogg",
    ".opus",
    ".wav",
    ".webm",
    ".wma",
}
BINARY_EXTENSIONS = {
    ".aab",
    ".apk",
    ".bin",
    ".dmg",
    ".exe",
    ".iso",
    ".zip",
}
SIGNING_EXTENSIONS = {".crt", ".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"}
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
PRIVATE_PATH_PARTS = {
    ".data",
    ".superpowers",
    "data",
    "logs",
    "media-tmp",
    "obsidian_vault",
    "outputs",
    "proofreading",
    "releases",
    "transcripts",
    "vault",
}
SAFE_HOSTS = {
    "docs.python.org",
    "example.com",
    "example.net",
    "example.org",
    "fastapi.tiangolo.com",
    "files.pythonhosted.org",
    "github.com",
    "opensource.org",
    "pypi.org",
    "raw.githubusercontent.com",
    "spdx.org",
    "starlette.io",
    "www.apache.org",
    "www.uvicorn.org",
}

CREDENTIAL_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_-]{12,}|"
    r"xox[baprs]-[A-Za-z0-9-]{12,}|AKIA[A-Z0-9]{16})"
)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
USER_HOME_RE = re.compile(r"/(?:Users|home)/[^\s'\"`]+")
URL_RE = re.compile(r"https?://(?P<host>[A-Za-z0-9.-]+)(?::\d+)?(?:[/\s'\"`]|$)")
BUCKET_RE = re.compile(r"(?:s3|gs)://[a-z0-9][a-z0-9.-]{2,}[a-z0-9](?:[/\s'\"`]|$)")


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    rule: str
    evidence: str


def audit_tree(root: Path) -> list[Finding]:
    """Return deterministic, redacted findings for public-tree candidates."""
    root = root.resolve()
    allowlist = _read_allowlist(root)
    findings: list[Finding] = []

    for path in _candidate_files(root):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            continue

        file_rule = _file_rule(relative, path, root, allowlist)
        if file_rule is not None:
            findings.append(Finding(relative, file_rule, f"<{file_rule}>"))
            continue

        findings.extend(_content_findings(relative, path))

    return findings


def _read_allowlist(root: Path) -> tuple[str, ...]:
    config = root / CONFIG_FILE
    if not config.is_file() or config.is_symlink():
        return ()
    entries: list[str] = []
    for line in config.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            entries.append(entry)
    return tuple(entries)


def _candidate_files(root: Path) -> list[Path]:
    tracked = _git_candidates(root)
    if tracked is not None:
        return tracked

    candidates: list[Path] = []
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory != ".git" and not (Path(current_root) / directory).is_symlink()
        )
        for filename in sorted(filenames):
            path = Path(current_root) / filename
            if path.is_file() or path.is_symlink():
                candidates.append(path)
    return candidates


def _git_candidates(root: Path) -> list[Path] | None:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None

    paths: list[Path] = []
    for encoded_path in result.stdout.split(b"\0"):
        if not encoded_path:
            continue
        path = root / os.fsdecode(encoded_path)
        if path.is_file() or path.is_symlink():
            paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def _file_rule(
    relative: str, path: Path, root: Path, allowlist: tuple[str, ...]
) -> str | None:
    parts = Path(relative).parts
    name = path.name
    suffix = path.suffix.lower()

    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "environment_file"
    if any(part in PRIVATE_PATH_PARTS for part in parts):
        return "private_path"
    if suffix in SIGNING_EXTENSIONS:
        return "signing_material"
    if suffix in DATABASE_EXTENSIONS:
        return "database_file"
    if suffix in MEDIA_EXTENSIONS:
        if _is_generated_fixture(relative, path, root):
            return None
        return "media_file"
    if suffix in BINARY_EXTENSIONS:
        if _is_generated_fixture(relative, path, root):
            return None
        return "binary_artifact"
    if not _is_allowlisted(relative, allowlist):
        return "not_allowlisted"
    return None


def _is_allowlisted(relative: str, allowlist: tuple[str, ...]) -> bool:
    if relative == CONFIG_FILE:
        return True
    for entry in allowlist:
        if entry.endswith("/") and relative.startswith(entry):
            return True
        if relative == entry:
            return True
    return False


def _is_generated_fixture(relative: str, path: Path, root: Path) -> bool:
    fixture_root = "tests/fixtures-synthetic/"
    if not relative.startswith(fixture_root):
        return False

    manifest = root / fixture_root / "MANIFEST.sha256"
    if not manifest.is_file() or manifest.is_symlink():
        return False
    expected_path = relative.removeprefix(fixture_root)
    expected_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if (
            len(parts) >= 3
            and parts[0] == expected_hash
            and parts[1] == expected_path
            and "generated=true" in parts[2:]
        ):
            return True
    return False


def _content_findings(relative: str, path: Path) -> list[Finding]:
    try:
        if path.stat().st_size > TEXT_LIMIT_BYTES:
            return []
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    for match in CREDENTIAL_RE.finditer(text):
        findings.append(Finding(relative, "credential", _redact_secret(match.group())))
    for match in IPV4_RE.finditer(text):
        if not _is_documented_ipv4(match.group()):
            findings.append(Finding(relative, "ipv4_literal", "<ipv4-literal>"))
    if USER_HOME_RE.search(text):
        findings.append(Finding(relative, "user_home_path", "<user-home-path>"))
    for match in URL_RE.finditer(text):
        if not _is_safe_host(match.group("host")):
            findings.append(Finding(relative, "deployment_endpoint", "<deployment-endpoint>"))
    if BUCKET_RE.search(text):
        findings.append(Finding(relative, "bucket_identifier", "<bucket-identifier>"))
    return findings


def _redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "<redacted-secret>"
    return f"{value[:4]}...{value[-4:]}"


def _is_documented_ipv4(value: str) -> bool:
    octets = [int(octet) for octet in value.split(".")]
    if any(octet > 255 for octet in octets):
        return False
    return (
        value in {"0.0.0.0", "127.0.0.1"}
        or octets[:3] == [192, 0, 2]
        or octets[:2] == [198, 51]
        or octets[:3] == [203, 0, 113]
    )


def _is_safe_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    return normalized in SAFE_HOSTS or normalized.endswith(".example.com")


def main() -> int:
    findings = audit_tree(Path(sys.argv[1]).resolve())
    for finding in findings:
        print(f"{finding.path}: {finding.rule}: {finding.evidence}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
