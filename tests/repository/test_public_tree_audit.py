from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.audit_public_tree import audit_tree


def write_allowlist(root: Path) -> None:
    (root / ".public-allowlist").write_text(
        "apps/\ndocs/\nscripts/\ntests/\nREADME.md\n", encoding="utf-8"
    )


def write_file(root: Path, relative_path: str, content: str | bytes) -> Path:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    return path


def findings_by_path(root: Path) -> dict[str, set[str]]:
    findings = audit_tree(root)
    by_path: dict[str, set[str]] = {}
    for finding in findings:
        by_path.setdefault(finding.path, set()).add(finding.rule)
    return by_path


def test_audit_tree_accepts_allowlisted_synthetic_content_and_documented_hosts(
    tmp_path: Path,
) -> None:
    """Removing safe-host exceptions would make this clean tree fail."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "README.md", "# Synthetic public repository\n")
    write_file(
        tmp_path,
        "apps/safe.py",
        "HOSTS = ['127.0.0.1', '192.0.2.10', 'https://example.com', "
        "'https://docs.python.org/3/']\n",
    )
    write_file(tmp_path, "docs/guide.md", "Use only generated examples.\n")

    assert audit_tree(tmp_path) == []


def test_audit_tree_rejects_private_files_and_paths(tmp_path: Path) -> None:
    """Removing a file/path deny rule would let private material through."""
    write_allowlist(tmp_path)
    write_file(tmp_path, ".env", "TOKEN=not-a-real-token\n")
    write_file(tmp_path, "apps/recording.m4a", b"synthetic-looking-but-unapproved")
    write_file(tmp_path, "apps/release.apk", b"synthetic-looking-but-unapproved")
    write_file(tmp_path, "apps/private.pem", "-----BEGIN PRIVATE KEY-----\n")
    write_file(tmp_path, "obsidian_vault/note.md", "private note\n")

    findings = findings_by_path(tmp_path)

    assert findings[".env"] == {"environment_file"}
    assert findings["apps/recording.m4a"] == {"media_file"}
    assert findings["apps/release.apk"] == {"binary_artifact"}
    assert findings["apps/private.pem"] == {"signing_material"}
    assert findings["obsidian_vault/note.md"] == {"private_path"}


def test_audit_tree_rejects_sensitive_source_values_and_redacts_credentials(
    tmp_path: Path,
) -> None:
    """Removing any content detector would expose operational or credential data."""
    write_allowlist(tmp_path)
    secret = "sk-" + "abcdefgh" + "ijklmnop"
    write_file(
        tmp_path,
        "apps/unsafe.py",
        "IP = '8" + ".8.8.8'\n"
        "HOME = '/" + "Users/alice/private'\n"
        f"TOKEN = '{secret}'\n"
        "ENDPOINT = 'https://" + "api.customer-production.invalid/v1'\n"
        "BUCKET = 's3://" + "customer-private-bucket/exports'\n",
    )

    findings = audit_tree(tmp_path)
    rules = {finding.rule for finding in findings}
    credential = next(finding for finding in findings if finding.rule == "credential")

    assert {"ipv4_literal", "user_home_path", "credential", "deployment_endpoint", "bucket_identifier"} <= rules
    assert credential.evidence == "sk-a...mnop"
    assert secret not in credential.evidence


def test_audit_tree_allows_only_hashed_generated_synthetic_media(tmp_path: Path) -> None:
    """Removing fixture validation would allow arbitrary media into the tree."""
    write_allowlist(tmp_path)
    media = write_file(tmp_path, "tests/fixtures-synthetic/sample.m4a", b"generated audio")
    digest = hashlib.sha256(media.read_bytes()).hexdigest()
    write_file(
        tmp_path,
        "tests/fixtures-synthetic/MANIFEST.sha256",
        f"{digest}  sample.m4a generated=true\n",
    )

    assert audit_tree(tmp_path) == []


def test_audit_tree_does_not_follow_symlinks(tmp_path: Path) -> None:
    """Following symlinks could scan or disclose content outside the repository."""
    write_allowlist(tmp_path)
    external = tmp_path.parent / "external-secret.txt"
    external.write_text("sk-" + "outside-repository-data", encoding="utf-8")
    (tmp_path / "apps").mkdir()
    (tmp_path / "apps" / "external-link.py").symlink_to(external)

    assert audit_tree(tmp_path) == []
