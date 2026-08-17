"""Audit the files eligible for inclusion in the public repository."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

TEXT_LIMIT_BYTES = 2 * 1024 * 1024
CONFIG_FILE = ".public-allowlist"

MEDIA_EXTENSIONS = {
    ".aac",
    ".aiff",
    ".amr",
    ".avi",
    ".caf",
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
    ".7z",
    ".apk",
    ".bin",
    ".dmg",
    ".exe",
    ".gz",
    ".ipa",
    ".iso",
    ".tar",
    ".whl",
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
    "example.invalid",
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
USER_HOME_RE = re.compile(r"(?i)(?:/(?:users|home)/|[a-z]:(?:\\+|/)users(?:\\+|/))")
URL_RE = re.compile(
    r"https?://(?:(?P<userinfo>[^@\s/?#]+)@)?"
    r"(?P<host>\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d+)?"
    r"(?P<suffix>(?:[/?#][^\s'\"`<>()\[\]{},;]*)?)",
    re.IGNORECASE,
)
BUCKET_RE = re.compile(
    r"(?:s3|gs)://[a-z0-9][a-z0-9.-]{2,}[a-z0-9](?:[/\s'\"`]|$)", re.IGNORECASE
)
SENSITIVE_QUERY_NAMES = {"api_key", "key", "password", "secret", "token", "access_token"}


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    rule: str
    evidence: str


def audit_tree(root: Path) -> list[Finding]:
    """Return deterministic, redacted findings for public-tree candidates."""
    root = root.resolve()
    allowlist = _read_allowlist(root)
    nested_git_paths = set(_nested_git_paths(root))
    findings = [
        Finding(relative, "nested_git", "<nested-git>")
        for relative in sorted(nested_git_paths)
    ]

    for path in _candidate_files(root):
        relative = path.relative_to(root).as_posix()
        if relative in nested_git_paths:
            continue
        if path.is_symlink():
            symlink_rule = _symlink_rule(relative, path, root, allowlist)
            if symlink_rule is not None:
                findings.append(Finding(relative, symlink_rule, f"<{symlink_rule}>"))
            continue

        file_rule = _file_rule(relative, path, root, allowlist)
        if file_rule is not None:
            findings.append(Finding(relative, file_rule, f"<{file_rule}>"))
            continue

        findings.extend(_content_findings(relative, path))

    return sorted(findings, key=lambda finding: (finding.path, finding.rule, finding.evidence))


def _read_allowlist(root: Path) -> tuple[str, ...]:
    config = root / CONFIG_FILE
    if not config.is_file() or config.is_symlink():
        return ()
    try:
        text = _read_bounded_utf8(config)
    except OSError:
        return ()
    if text is None:
        return ()
    entries: list[str] = []
    for line in text.splitlines():
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
        next_directories: list[str] = []
        for directory in sorted(directories):
            path = Path(current_root) / directory
            if path.is_symlink():
                candidates.append(path)
            elif directory.casefold() != ".git":
                next_directories.append(directory)
        directories[:] = next_directories
        for filename in sorted(filenames):
            path = Path(current_root) / filename
            if path.is_file() or path.is_symlink():
                candidates.append(path)
    return candidates


def _nested_git_paths(root: Path) -> list[str]:
    findings: list[str] = []
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_root)
        next_directories: list[str] = []
        for directory in sorted(directories):
            path = current / directory
            if directory.casefold() == ".git":
                if path != root / ".git":
                    findings.append(path.relative_to(root).as_posix())
                continue
            if not path.is_symlink():
                next_directories.append(directory)
        directories[:] = next_directories
        for filename in sorted(filenames):
            path = current / filename
            if filename.casefold() == ".git" and path != root / ".git":
                findings.append(path.relative_to(root).as_posix())
    return findings


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
    intrinsic_rule = _intrinsic_rule(relative, path.suffix.lower())
    if intrinsic_rule is not None:
        return intrinsic_rule

    suffix = path.suffix.lower()

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


def _intrinsic_rule(relative: str, suffix: str) -> str | None:
    parts = tuple(part.casefold() for part in Path(relative).parts)
    name = parts[-1]

    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "environment_file"
    if any(part in PRIVATE_PATH_PARTS for part in parts):
        return "private_path"
    if suffix in SIGNING_EXTENSIONS:
        return "signing_material"
    if suffix in DATABASE_EXTENSIONS:
        return "database_file"
    return None


def _symlink_rule(
    relative: str, path: Path, root: Path, allowlist: tuple[str, ...]
) -> str | None:
    intrinsic_rule = _intrinsic_rule(relative, path.suffix.lower())
    if intrinsic_rule is not None:
        return intrinsic_rule
    if path.suffix.lower() in MEDIA_EXTENSIONS:
        return "media_file"
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return "binary_artifact"
    if not _is_allowlisted(relative, allowlist):
        return "not_allowlisted"

    try:
        target = os.readlink(path)
    except OSError:
        return "UNINSPECTABLE_SYMLINK"
    if _contains_user_home_path(target):
        return "symlink_user_home_target"
    if _is_absolute_target(target):
        return "symlink_absolute_target"

    target_path = Path(os.path.normpath(str(path.parent / target)))
    try:
        target_relative = target_path.relative_to(root).as_posix()
    except ValueError:
        return "symlink_outside_root"
    target_rule = _intrinsic_rule(target_relative, target_path.suffix.lower())
    if target_rule is not None:
        return f"symlink_target_{target_rule}"
    if not _is_allowlisted(target_relative, allowlist):
        return "symlink_target_not_allowlisted"
    if target_path.is_symlink():
        return "symlink_target_is_symlink"
    if not target_path.exists():
        return "broken_symlink"
    return None


def _is_absolute_target(target: str) -> bool:
    return target.startswith("/") or bool(re.match(r"(?i)^[a-z]:[\\/]", target))


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
    try:
        expected_hash = _sha256_file(path)
        manifest_text = _read_bounded_utf8(manifest)
    except OSError:
        return False
    if manifest_text is None:
        return False
    for line in manifest_text.splitlines():
        parts = line.split()
        if (
            len(parts) >= 3
            and parts[0] == expected_hash
            and parts[1] == expected_path
            and "generated=true" in parts[2:]
        ):
            return True
    return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _content_findings(relative: str, path: Path) -> list[Finding]:
    try:
        if path.stat().st_size > TEXT_LIMIT_BYTES:
            return [Finding(relative, "TEXT_TOO_LARGE", "<text-too-large>")]
        content = _read_bounded_bytes(path)
    except OSError:
        return [Finding(relative, "UNINSPECTABLE_TEXT", "<uninspectable-text>")]
    if len(content) > TEXT_LIMIT_BYTES:
        return [Finding(relative, "TEXT_TOO_LARGE", "<text-too-large>")]
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return [Finding(relative, "UNINSPECTABLE_TEXT", "<uninspectable-text>")]

    findings: list[Finding] = []
    for match in CREDENTIAL_RE.finditer(text):
        findings.append(Finding(relative, "credential", _redact_secret(match.group())))
    for match in IPV4_RE.finditer(text):
        if not _is_documented_ipv4(match.group()):
            findings.append(Finding(relative, "ipv4_literal", "<ipv4-literal>"))
    if _contains_user_home_path(text):
        findings.append(Finding(relative, "user_home_path", "<user-home-path>"))
    for match in URL_RE.finditer(text):
        if match.group("userinfo") or _has_sensitive_query_parameter(match.group("suffix")):
            findings.append(Finding(relative, "credential", "<url-credential>"))
        if not _is_safe_url_host(match.group("host")):
            findings.append(Finding(relative, "deployment_endpoint", "<deployment-endpoint>"))
    if BUCKET_RE.search(text):
        findings.append(Finding(relative, "bucket_identifier", "<bucket-identifier>"))
    return findings


def _read_bounded_bytes(path: Path) -> bytes:
    with path.open("rb") as source:
        return source.read(TEXT_LIMIT_BYTES + 1)


def _read_bounded_utf8(path: Path) -> str | None:
    content = _read_bounded_bytes(path)
    if len(content) > TEXT_LIMIT_BYTES:
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _contains_user_home_path(value: str) -> bool:
    return USER_HOME_RE.search(value) is not None


def _has_sensitive_query_parameter(suffix: str) -> bool:
    query = urlsplit("https://example.invalid" + suffix).query
    return any(name.casefold() in SENSITIVE_QUERY_NAMES for name, _ in parse_qsl(query, keep_blank_values=True))


def _redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "<redacted-secret>"
    return f"{value[:4]}...{value[-4:]}"


def _is_documented_ipv4(value: str) -> bool:
    octets = [int(octet) for octet in value.split(".")]
    if len(octets) != 4 or any(octet > 255 for octet in octets):
        return False
    return (
        value in {"0.0.0.0", "127.0.0.1"}
        or octets[:3] == [192, 0, 2]
        or octets[:3] == [198, 51, 100]
        or octets[:3] == [203, 0, 113]
    )


def _is_safe_host(host: str) -> bool:
    normalized = host.lower().rstrip(".")
    return normalized in SAFE_HOSTS or normalized.endswith(".example.com")


def _is_safe_url_host(host: str) -> bool:
    normalized = host.strip("[]")
    if normalized.casefold() == "localhost" or normalized == "::1":
        return True
    if IPV4_RE.fullmatch(normalized):
        return _is_documented_ipv4(normalized)
    return _is_safe_host(normalized)


def main() -> int:
    findings = audit_tree(Path(sys.argv[1]).resolve())
    for finding in findings:
        print(f"{finding.path}: {finding.rule}: {finding.evidence}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
