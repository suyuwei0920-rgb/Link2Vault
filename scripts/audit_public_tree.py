"""Audit the files eligible for inclusion in the public repository."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
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
SIGNING_EXTENSIONS = {
    ".cer",
    ".crt",
    ".der",
    ".jks",
    ".key",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".p8",
    ".pem",
    ".pfx",
    ".ppk",
}
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
RUNTIME_ARTIFACT_EXTENSIONS = {".log", ".srt", ".vtt"}
PRIVATE_PATH_PARTS = {
    ".data",
    ".superpowers",
    "data",
    "logs",
    "media-tmp",
    "obsidian_vault",
    "outputs",
    "proofreading",
    "recordings",
    "releases",
    "transcripts",
    "vault",
}
GENERATED_PATH_PARTS = {
    ".mypy_cache",
    ".next",
    ".nox",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".svelte-kit",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "env",
    "node_modules",
    "venv",
}
IDE_PATH_PARTS = {".idea", ".vscode"}
SAFE_HOSTS = {
    "api.github.com",
    "astral.sh",
    "docs.docker.com",
    "docs.python.org",
    "example.com",
    "example.invalid",
    "example.net",
    "example.org",
    "fastapi.tiangolo.com",
    "files.pythonhosted.org",
    "docker.io",
    "ghcr.io",
    "github.com",
    "hub.docker.com",
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
DSN_BASE_SCHEMES = (
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "redis",
    "rediss",
    "mongodb",
    "amqp",
    "amqps",
    "kafka",
    "nats",
)
DSN_BASE_PATTERN = "|".join(
    sorted(
        (re.escape(scheme) for scheme in DSN_BASE_SCHEMES),
        key=len,
        reverse=True,
    )
)
DSN_SCHEME_PATTERN = rf"(?:{DSN_BASE_PATTERN})(?:\+[a-z0-9][a-z0-9._-]*)?"
NETWORK_SCHEME_PATTERN = rf"(?:https?|{DSN_SCHEME_PATTERN})"
DNS_LABEL_PATTERN = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DNS_TLD_PATTERN = r"(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9]))"
DNS_HOST_PATTERN = rf"(?:{DNS_LABEL_PATTERN}\.)+{DNS_TLD_PATTERN}"
IPV6_LITERAL_PATTERN = r"\[[0-9a-f:.]+(?:%25[a-z0-9._~-]+|%[a-z0-9._~-]+)?\]"
URL_HOST_PATTERN = (
    rf"(?:{IPV6_LITERAL_PATTERN}|"
    rf"(?:{DNS_LABEL_PATTERN}\.)*{DNS_LABEL_PATTERN}\.?)"
)
URL_RE = re.compile(
    rf"(?P<scheme>{NETWORK_SCHEME_PATTERN})://"
    rf"(?:(?P<userinfo>[^@\s/?#]+)@)?(?P<host>{URL_HOST_PATTERN})(?::\d+)?"
    r"(?P<suffix>(?:[/?#][^\s'\"`<>()\[\]{},;]*)?)(?![a-z0-9_.-])",
    re.IGNORECASE,
)
ASSIGNED_ENDPOINT_RE = re.compile(
    rf'''(?im)(?:^|[^a-z0-9_])[\x60'\"]?'''
    rf'''(?P<key>(?:(?:[a-z0-9]+_)*(?:url|uri|dsn)|(?:[a-z0-9]+_)*webhook))'''
    rf'''[\x60'\"]?[\t ]*[:=][\t ]*[\x60'\"]?'''
    rf'''(?P<value>(?:DUMMY_)?(?:'''
    rf'''(?:{NETWORK_SCHEME_PATTERN})://[^\s\x60'\"<>]+|'''
    rf'''{DNS_HOST_PATTERN}(?::[0-9]{{1,5}})?|'''
    rf'''{IPV6_LITERAL_PATTERN}(?::[0-9]{{1,5}})?'''
    rf'''))(?![a-z0-9_.-])'''
)
BUCKET_RE = re.compile(
    r"(?:s3|gs)://[a-z0-9][a-z0-9.-]{2,}[a-z0-9](?:[/\s'\"`]|$)", re.IGNORECASE
)
SENSITIVE_QUERY_NAMES = {"api_key", "key", "password", "secret", "token", "access_token"}
PATH_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>api[_-]?key|access[_-]?token|password|secret|token)"
    r"(?P<separator>[=:])[^/\\]+"
)
PATH_NETWORK_ENDPOINT_RE = re.compile(
    rf"(?i)\b(?:{NETWORK_SCHEME_PATTERN}):/*[^\s\\]*"
)
PATH_DEPLOYMENT_HOST_RE = re.compile(
    rf"(?i)\b(?:api|app|auth|admin|prod|production|staging|stage|dev|internal|"
    rf"backend|webhook|hooks|service|gateway|upload|download|cdn|storage|db|"
    rf"database|redis|mqtt|s3|cos|kb|worker)\.(?:{DNS_LABEL_PATTERN}\.)+"
    rf"{DNS_TLD_PATTERN}\b"
)


def _sanitize_finding_path(path: str) -> str:
    """Redact path-borne secrets and neutralize control/log delimiter injection."""
    sanitized = CREDENTIAL_RE.sub("<redacted-secret>", path)
    sanitized = USER_HOME_RE.sub("/<redacted-home>/", sanitized)
    sanitized = PATH_NETWORK_ENDPOINT_RE.sub("<redacted-endpoint>", sanitized)
    sanitized = PATH_DEPLOYMENT_HOST_RE.sub("<redacted-endpoint>", sanitized)
    sanitized = PATH_SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: (
            match.group("key")
            + match.group("separator")
            + "<redacted-secret>"
        ),
        sanitized,
    )

    escaped: list[str] = []
    for character in sanitized:
        codepoint = ord(character)
        if character == "\t":
            escaped.append(r"\t")
        elif character == "\n":
            escaped.append(r"\n")
        elif character == "\r":
            escaped.append(r"\r")
        elif codepoint < 32 or 127 <= codepoint <= 159:
            escaped.append(f"\\x{codepoint:02x}")
        else:
            escaped.append(character)
    return "".join(escaped).replace(": ", r":\x20")


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    rule: str
    evidence: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _sanitize_finding_path(self.path))


def audit_tree(root: Path) -> list[Finding]:
    """Return deterministic, redacted findings for public-tree candidates."""
    root = root.resolve()
    nested_git_paths = set(_nested_git_paths(root))
    findings = [
        Finding(relative, "nested_git", "<nested-git>")
        for relative in sorted(nested_git_paths)
    ]

    index_entries = _git_index_entries(root)
    if index_entries is not None:
        findings.extend(_audit_index(root, index_entries, nested_git_paths))

    allowlist = _read_allowlist(root)
    for path in _worktree_candidates(root):
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
        if _is_generated_fixture_suffix(path.suffix.lower()):
            continue

        findings.extend(_content_findings(relative, path))

    return sorted(
        set(findings),
        key=lambda finding: (finding.path, finding.rule, finding.evidence),
    )


def audit_history(root: Path, revision: str) -> list[Finding]:
    """Audit every Git tree reachable from revision without checking it out."""
    root = root.resolve()
    shallow = _is_shallow_repository(root)
    if shallow is not False:
        rule = "SHALLOW_HISTORY" if shallow else "UNINSPECTABLE_HISTORY"
        evidence = "<shallow-history>" if shallow else "<uninspectable-history>"
        return [Finding(f"{revision}:<history>", rule, evidence)]
    commits = _reachable_commits(root, revision)
    if not commits:
        return [
            Finding(
                f"{revision}:<history>",
                "UNINSPECTABLE_HISTORY",
                "<uninspectable-history>",
            )
        ]

    tip_entries = _git_tree_entries(root, commits[0])
    if tip_entries is None:
        return [
            Finding(
                f"{commits[0]}:<tree>",
                "UNINSPECTABLE_HISTORY",
                "<uninspectable-history>",
            )
        ]
    tip_by_path = {entry.relative: entry for entry in tip_entries}
    allowlist = _allowlist_entries(_index_text(root, tip_by_path.get(CONFIG_FILE)))

    findings: list[Finding] = []
    for commit in commits:
        entries = _git_tree_entries(root, commit)
        if entries is None:
            findings.append(
                Finding(
                    f"{commit}:<tree>",
                    "UNINSPECTABLE_HISTORY",
                    "<uninspectable-history>",
                )
            )
            continue
        findings.extend(_audit_history_commit(root, commit, entries, allowlist))

    return sorted(
        set(findings),
        key=lambda finding: (finding.path, finding.rule, finding.evidence),
    )


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
    return _allowlist_entries(text)


def _allowlist_entries(text: str | None) -> tuple[str, ...]:
    if text is None:
        return ()
    entries: list[str] = []
    for line in text.splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            entries.append(entry)
    return tuple(entries)


def _index_blob_size(root: Path, entry: _IndexEntry) -> int | None:
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "-s", entry.object_id],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def _index_blob(root: Path, entry: _IndexEntry, *, limit: int) -> bytes | None:
    size = _index_blob_size(root, entry)
    if size is None or size > limit:
        return None
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "blob", entry.object_id],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0 or len(result.stdout) != size:
        return None
    return result.stdout


def _index_text(root: Path, entry: _IndexEntry | None) -> str | None:
    if entry is None:
        return None
    content = _index_blob(root, entry, limit=TEXT_LIMIT_BYTES)
    if content is None:
        return None
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _worktree_candidates(root: Path) -> list[Path]:
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


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    relative: str
    mode: str
    object_id: str
    object_type: str = "blob"


def _reachable_commits(root: Path, revision: str) -> list[str] | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-list", revision],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    commits = [line for line in result.stdout.splitlines() if line]
    if not commits or any(re.fullmatch(r"[0-9a-f]{40,64}", commit) is None for commit in commits):
        return None
    return commits


def _is_shallow_repository(root: Path) -> bool | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-shallow-repository"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    normalized = result.stdout.strip().casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    return None


def _git_tree_entries(root: Path, commit: str) -> list[_IndexEntry] | None:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-tree", "-r", "-z", "--full-tree", commit],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None

    entries: list[_IndexEntry] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", maxsplit=1)
            mode, object_type, object_id = metadata.decode("ascii").split()
        except (UnicodeDecodeError, ValueError):
            return None
        entries.append(
            _IndexEntry(
                relative=os.fsdecode(encoded_path),
                mode=mode,
                object_id=object_id,
                object_type=object_type,
            )
        )
    return sorted(entries, key=lambda entry: entry.relative)


def _git_index_entries(root: Path) -> list[_IndexEntry] | None:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--stage", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return None

    entries: list[_IndexEntry] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, encoded_path = record.split(b"\t", maxsplit=1)
            mode, object_id, stage = metadata.decode("ascii").split()
        except (UnicodeDecodeError, ValueError):
            continue
        if stage != "0":
            continue
        entries.append(
            _IndexEntry(
                relative=os.fsdecode(encoded_path),
                mode=mode,
                object_id=object_id,
            )
        )
    return sorted(entries, key=lambda entry: entry.relative)


def _audit_index(
    root: Path,
    entries: list[_IndexEntry],
    nested_git_paths: set[str],
) -> list[Finding]:
    entry_by_path = {entry.relative: entry for entry in entries}
    allowlist_text = _index_text(root, entry_by_path.get(CONFIG_FILE))
    allowlist = _allowlist_entries(allowlist_text)
    manifest_entry = entry_by_path.get("tests/fixtures-synthetic/MANIFEST.sha256")
    manifest_text = _index_text(root, manifest_entry)
    findings: list[Finding] = []

    for entry in entries:
        relative = entry.relative
        if relative in nested_git_paths:
            continue
        suffix = Path(relative).suffix.lower()
        intrinsic_rule = _intrinsic_rule(relative, suffix)
        if intrinsic_rule is not None:
            findings.append(Finding(relative, intrinsic_rule, f"<{intrinsic_rule}>"))
            continue

        if entry.mode == "120000":
            target_bytes = _index_blob(root, entry, limit=TEXT_LIMIT_BYTES)
            if target_bytes is None:
                findings.append(
                    Finding(relative, "UNINSPECTABLE_SYMLINK", "<uninspectable-symlink>")
                )
                continue
            try:
                target = target_bytes.decode("utf-8")
            except UnicodeDecodeError:
                findings.append(
                    Finding(relative, "UNINSPECTABLE_SYMLINK", "<uninspectable-symlink>")
                )
                continue
            symlink_rule = _index_symlink_rule(
                relative, target, allowlist, entry_by_path
            )
            if symlink_rule is not None:
                findings.append(Finding(relative, symlink_rule, f"<{symlink_rule}>"))
            continue

        file_rule = _index_file_rule(
            relative,
            suffix,
            root,
            entry,
            allowlist,
            manifest_text,
        )
        if file_rule is not None:
            findings.append(Finding(relative, file_rule, f"<{file_rule}>"))
            continue
        if _is_generated_fixture_suffix(suffix):
            continue

        size = _index_blob_size(root, entry)
        if size is None:
            findings.append(
                Finding(relative, "UNINSPECTABLE_TEXT", "<uninspectable-text>")
            )
            continue
        if size > TEXT_LIMIT_BYTES:
            findings.append(Finding(relative, "TEXT_TOO_LARGE", "<text-too-large>"))
            continue
        content = _index_blob(root, entry, limit=TEXT_LIMIT_BYTES)
        if content is None:
            findings.append(
                Finding(relative, "UNINSPECTABLE_TEXT", "<uninspectable-text>")
            )
            continue
        findings.extend(_content_findings_from_bytes(relative, content))

    return findings


def _audit_history_commit(
    root: Path,
    commit: str,
    entries: list[_IndexEntry],
    allowlist: tuple[str, ...],
) -> list[Finding]:
    entry_by_path = {entry.relative: entry for entry in entries}
    manifest_entry = entry_by_path.get("tests/fixtures-synthetic/MANIFEST.sha256")
    manifest_text = (
        _index_text(root, manifest_entry)
        if manifest_entry is not None and manifest_entry.mode in {"100644", "100755"}
        else None
    )
    findings: list[Finding] = []

    for entry in entries:
        relative = entry.relative
        display_path = f"{commit}:{relative}"
        suffix = Path(relative).suffix.lower()

        if any(part.casefold() == ".git" for part in Path(relative).parts):
            findings.append(Finding(display_path, "nested_git", "<nested-git>"))
            continue

        intrinsic_rule = _intrinsic_rule(relative, suffix)
        if intrinsic_rule is not None:
            findings.append(
                Finding(display_path, intrinsic_rule, f"<{intrinsic_rule}>")
            )
            continue

        if entry.mode == "160000" or entry.object_type == "commit":
            findings.append(Finding(display_path, "gitlink", "<gitlink>"))
            continue

        if entry.object_type != "blob" or entry.mode not in {
            "100644",
            "100755",
            "120000",
        }:
            findings.append(
                Finding(display_path, "UNSUPPORTED_GIT_MODE", "<unsupported-git-mode>")
            )
            continue

        if entry.mode == "120000":
            target_bytes = _index_blob(root, entry, limit=TEXT_LIMIT_BYTES)
            if target_bytes is None:
                findings.append(
                    Finding(
                        display_path,
                        "UNINSPECTABLE_SYMLINK",
                        "<uninspectable-symlink>",
                    )
                )
                continue
            try:
                target = target_bytes.decode("utf-8")
            except UnicodeDecodeError:
                findings.append(
                    Finding(
                        display_path,
                        "UNINSPECTABLE_SYMLINK",
                        "<uninspectable-symlink>",
                    )
                )
                continue
            symlink_rule = _index_symlink_rule(
                relative, target, allowlist, entry_by_path
            )
            if symlink_rule is not None:
                findings.append(
                    Finding(display_path, symlink_rule, f"<{symlink_rule}>")
                )
            continue

        file_rule = _index_file_rule(
            relative,
            suffix,
            root,
            entry,
            allowlist,
            manifest_text,
        )
        if file_rule is not None:
            findings.append(Finding(display_path, file_rule, f"<{file_rule}>"))
            continue
        if _is_generated_fixture_suffix(suffix):
            continue

        size = _index_blob_size(root, entry)
        if size is None:
            findings.append(
                Finding(
                    display_path, "UNINSPECTABLE_TEXT", "<uninspectable-text>"
                )
            )
            continue
        if size > TEXT_LIMIT_BYTES:
            findings.append(
                Finding(display_path, "TEXT_TOO_LARGE", "<text-too-large>")
            )
            continue
        content = _index_blob(root, entry, limit=TEXT_LIMIT_BYTES)
        if content is None:
            findings.append(
                Finding(
                    display_path, "UNINSPECTABLE_TEXT", "<uninspectable-text>"
                )
            )
            continue
        findings.extend(_content_findings_from_bytes(display_path, content))

    return findings


def _nested_git_paths(root: Path) -> list[str]:
    findings: list[str] = []
    tracked_prefixes = _tracked_directory_prefixes(root)
    for current_root, directories, filenames in os.walk(root, followlinks=False):
        current = Path(current_root)
        next_directories: list[str] = []
        for directory in sorted(directories):
            path = current / directory
            if directory.casefold() == ".git":
                if path != root / ".git":
                    findings.append(path.relative_to(root).as_posix())
                continue
            if path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if relative not in tracked_prefixes and _is_git_ignored(root, relative):
                continue
            next_directories.append(directory)
        directories[:] = next_directories
        for filename in sorted(filenames):
            path = current / filename
            if filename.casefold() == ".git" and path != root / ".git":
                findings.append(path.relative_to(root).as_posix())
    return findings


def _tracked_directory_prefixes(root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "-z"],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        return set()
    prefixes: set[str] = set()
    for encoded_path in result.stdout.split(b"\0"):
        if not encoded_path:
            continue
        path = Path(os.fsdecode(encoded_path))
        for parent in path.parents:
            if parent == Path("."):
                break
            prefixes.add(parent.as_posix())
    return prefixes


def _is_git_ignored(root: Path, relative: str) -> bool:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "check-ignore",
            "--quiet",
            "--no-index",
            "--",
            relative,
        ],
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


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
        return "binary_artifact"
    if not _is_allowlisted(relative, allowlist):
        return "not_allowlisted"
    return None


def _index_file_rule(
    relative: str,
    suffix: str,
    root: Path,
    entry: _IndexEntry,
    allowlist: tuple[str, ...],
    manifest_text: str | None,
) -> str | None:
    if suffix in MEDIA_EXTENSIONS:
        if _is_generated_index_fixture(
            relative, root, entry, manifest_text
        ):
            return None
        return "media_file"
    if suffix in BINARY_EXTENSIONS:
        return "binary_artifact"
    if not _is_allowlisted(relative, allowlist):
        return "not_allowlisted"
    return None


def _intrinsic_rule(relative: str, suffix: str) -> str | None:
    parts = tuple(part.casefold() for part in Path(relative).parts)
    name = parts[-1]

    if (
        (name.startswith(".env") or name.endswith(".env"))
        and name != ".env.example"
    ):
        return "environment_file"
    if any(part in PRIVATE_PATH_PARTS for part in parts):
        return "private_path"
    if any(part in GENERATED_PATH_PARTS for part in parts):
        return "generated_path"
    if any(part in IDE_PATH_PARTS for part in parts):
        return "ide_state"
    if suffix in RUNTIME_ARTIFACT_EXTENSIONS or ".transcript." in name:
        return "runtime_artifact"
    if name.endswith(("-wal", "-shm", "-journal")):
        return "database_sidecar"
    if suffix in {".pyc", ".pyo", ".pyd"} or name.endswith("$py.class"):
        return "generated_file"
    if suffix == ".iml" or name in {".ds_store", "thumbs.db"}:
        return "ide_state"
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


def _index_symlink_rule(
    relative: str,
    target: str,
    allowlist: tuple[str, ...],
    entry_by_path: dict[str, _IndexEntry],
) -> str | None:
    suffix = Path(relative).suffix.lower()
    if suffix in MEDIA_EXTENSIONS:
        return "media_file"
    if suffix in BINARY_EXTENSIONS:
        return "binary_artifact"
    if not _is_allowlisted(relative, allowlist):
        return "not_allowlisted"
    if _contains_user_home_path(target):
        return "symlink_user_home_target"
    if _is_absolute_target(target):
        return "symlink_absolute_target"

    target_path = Path(os.path.normpath(str(Path(relative).parent / target)))
    if target_path.is_absolute() or target_path.parts[:1] == ("..",):
        return "symlink_outside_root"
    target_relative = target_path.as_posix()
    target_rule = _intrinsic_rule(target_relative, target_path.suffix.lower())
    if target_rule is not None:
        return f"symlink_target_{target_rule}"
    if not _is_allowlisted(target_relative, allowlist):
        return "symlink_target_not_allowlisted"
    target_entry = entry_by_path.get(target_relative)
    if target_entry is None:
        target_prefix = target_relative.rstrip("/") + "/"
        if any(path.startswith(target_prefix) for path in entry_by_path):
            return None
        return "broken_symlink"
    if target_entry.mode == "120000":
        return "symlink_target_is_symlink"
    if target_entry.mode not in {"100644", "100755"}:
        return "symlink_target_unsupported_mode"
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
    try:
        if path.stat().st_size > TEXT_LIMIT_BYTES:
            return False
    except OSError:
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


def _is_generated_index_fixture(
    relative: str,
    root: Path,
    entry: _IndexEntry,
    manifest_text: str | None,
) -> bool:
    fixture_root = "tests/fixtures-synthetic/"
    if not relative.startswith(fixture_root) or manifest_text is None:
        return False
    content = _index_blob(root, entry, limit=TEXT_LIMIT_BYTES)
    if content is None:
        return False
    expected_path = relative.removeprefix(fixture_root)
    expected_hash = hashlib.sha256(content).hexdigest()
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


def _is_generated_fixture_suffix(suffix: str) -> bool:
    return suffix in MEDIA_EXTENSIONS


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
    return _content_findings_from_bytes(relative, content)


def _content_findings_from_bytes(relative: str, content: bytes) -> list[Finding]:
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
    for match in ASSIGNED_ENDPOINT_RE.finditer(text):
        value = match.group("value")
        normalized_target = value.removeprefix("DUMMY_")
        if "://" in normalized_target:
            parsed = urlsplit(normalized_target)
            if (
                parsed.username is not None
                or parsed.password is not None
                or _has_sensitive_query_parameter("?" + parsed.query)
            ):
                findings.append(Finding(relative, "credential", "<url-credential>"))
            network_location = parsed.hostname or ""
        elif normalized_target.startswith("[") and "]" in normalized_target:
            network_location = normalized_target[: normalized_target.index("]") + 1]
        else:
            network_location = normalized_target.rsplit(":", maxsplit=1)[0]
        if not _is_safe_url_host(network_location):
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
    if normalized in SAFE_HOSTS:
        return True
    return normalized in {"example.test", "localhost"} or normalized.endswith(
        (
            ".example.com",
            ".example.invalid",
            ".example.net",
            ".example.org",
            ".example.test",
        )
    )


def _is_safe_url_host(host: str) -> bool:
    normalized = host.strip("[]").rstrip(".")
    if normalized.casefold() == "localhost" or normalized == "::1":
        return True
    if IPV4_RE.fullmatch(normalized):
        return _is_documented_ipv4(normalized)
    return _is_safe_host(normalized)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument(
        "--history",
        metavar="REVISION",
        help="audit every Git tree reachable from REVISION without checkout",
    )
    arguments = parser.parse_args()
    root = Path(arguments.root).resolve()
    findings = (
        audit_history(root, arguments.history)
        if arguments.history is not None
        else audit_tree(root)
    )
    for finding in findings:
        print(f"{finding.path}: {finding.rule}: {finding.evidence}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
