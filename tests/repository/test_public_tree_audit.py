from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.audit_public_tree import audit_tree

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def gitleaks_rule(rule_id: str) -> dict[str, object]:
    for config_name in (".gitleaks.toml", ".gitleaks-paths.toml"):
        with (REPOSITORY_ROOT / config_name).open("rb") as config_file:
            config = tomllib.load(config_file)
        for rule in config["rules"]:
            if rule["id"] == rule_id:
                return rule
    raise AssertionError(f"missing Gitleaks rule: {rule_id}")


def gitleaks_rule_findings(rule: dict[str, object], text: str) -> list[str]:
    pattern = re.compile(str(rule["regex"]))
    secret_group = int(rule["secretGroup"])
    findings: list[str] = []
    for match in pattern.finditer(text):
        secret = match.group(secret_group)
        allowlisted = any(
            re.search(allow_regex, secret)
            for allowlist in rule.get("allowlists", [])
            for allow_regex in allowlist.get("regexes", [])
        )
        if not allowlisted:
            findings.append(secret)
    return findings


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
        "'https://example.invalid', 'https://docs.python.org/3/']\n",
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
    """External link targets must be rejected without scanning their contents."""
    write_allowlist(tmp_path)
    external = tmp_path.parent / "external-secret.txt"
    external.write_text("sk-" + "outside-repository-data", encoding="utf-8")
    (tmp_path / "apps").mkdir()
    (tmp_path / "apps" / "external-link.py").symlink_to(external)

    findings = audit_tree(tmp_path)

    assert [(finding.path, finding.rule, finding.evidence) for finding in findings] == [
        ("apps/external-link.py", "symlink_absolute_target", "<symlink_absolute_target>")
    ]


def initialize_git_repository(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)


def test_audit_tree_uses_git_candidates_and_only_reports_force_added_env_files(
    tmp_path: Path,
) -> None:
    """Including ignored runtime files would violate the tracked-candidate scope."""
    write_allowlist(tmp_path)
    write_file(tmp_path, ".gitignore", ".env\n")
    write_file(tmp_path, "README.md", "# public\n")
    write_file(tmp_path, "apps/safe.py", "VALUE = 'public'\n")
    write_file(tmp_path, ".env", "TOKEN=runtime-only\n")
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    write_file(tmp_path, "apps/untracked.m4a", b"untracked candidate")

    findings = findings_by_path(tmp_path)
    assert ".env" not in findings
    assert findings["apps/untracked.m4a"] == {"media_file"}

    subprocess.run(["git", "add", "-f", ".env"], cwd=tmp_path, check=True)

    assert findings_by_path(tmp_path)[".env"] == {"environment_file"}


def test_audit_tree_rejects_nested_git_control_directories_in_git_mode(
    tmp_path: Path,
) -> None:
    """Pruning nested Git control directories would hide donor history."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "README.md", "# public\n")
    write_file(tmp_path, "apps/embedded/.git/config", "[core]\n")
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "README.md", ".public-allowlist"], cwd=tmp_path, check=True)

    findings = audit_tree(tmp_path)

    assert any(
        finding.path == "apps/embedded/.git" and finding.rule == "nested_git"
        for finding in findings
    )
    assert not any(finding.path == ".git" for finding in findings)


def test_audit_tree_fails_closed_for_oversized_and_uninspectable_text(
    tmp_path: Path,
) -> None:
    """Returning no finding for unreadable allowed source would expose it."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "apps/oversized.py", "x" * (2 * 1024 * 1024 + 1))
    write_file(tmp_path, "apps/invalid.py", b"\xff\xfe\x00")

    findings = findings_by_path(tmp_path)

    assert findings["apps/oversized.py"] == {"TEXT_TOO_LARGE"}
    assert findings["apps/invalid.py"] == {"UNINSPECTABLE_TEXT"}


def test_audit_tree_validates_symlink_metadata_without_following_targets(
    tmp_path: Path,
) -> None:
    """Silently skipping symlink objects could hide unsafe repository links."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "apps/target.txt", "safe\n")
    external = tmp_path.parent / "outside-target.txt"
    external.write_text("outside\n", encoding="utf-8")
    (tmp_path / "apps" / "safe-link.txt").symlink_to("target.txt")
    (tmp_path / "apps" / "private-link.pem").symlink_to("target.txt")
    (tmp_path / "apps" / "absolute-link.txt").symlink_to(external)
    (tmp_path / "apps" / "outside-link.txt").symlink_to("../../outside-target.txt")
    (tmp_path / "apps" / "home-link.txt").symlink_to("/" + "Users/alice/private")
    (tmp_path / "apps" / "broken-link.txt").symlink_to("missing.txt")

    findings = findings_by_path(tmp_path)

    assert "apps/safe-link.txt" not in findings
    assert findings["apps/private-link.pem"] == {"signing_material"}
    assert findings["apps/absolute-link.txt"] == {"symlink_absolute_target"}
    assert findings["apps/outside-link.txt"] == {"symlink_outside_root"}
    assert findings["apps/home-link.txt"] == {"symlink_user_home_target"}
    assert findings["apps/broken-link.txt"] == {"broken_symlink"}


def test_audit_tree_matches_private_names_and_extensions_case_insensitively(
    tmp_path: Path,
) -> None:
    """Case-sensitive deny rules would allow platform-variant private files."""
    write_allowlist(tmp_path)
    write_file(tmp_path, ".ENV", "TOKEN=runtime-only\n")
    write_file(tmp_path, "apps/recording.AMR", b"audio")
    write_file(tmp_path, "apps/recording.AIFF", b"audio")
    write_file(tmp_path, "apps/recording.CAF", b"audio")
    write_file(tmp_path, "apps/release.7Z", b"archive")
    write_file(tmp_path, "apps/release.TAR", b"archive")
    write_file(tmp_path, "apps/release.GZ", b"archive")
    write_file(tmp_path, "apps/release.IPA", b"package")
    write_file(tmp_path, "apps/release.WHL", b"package")
    write_file(tmp_path, "apps/.Superpowers/note.md", "private\n")
    write_file(tmp_path, "apps/Transcripts/note.md", "private\n")

    findings = findings_by_path(tmp_path)

    assert findings[".ENV"] == {"environment_file"}
    assert findings["apps/recording.AMR"] == {"media_file"}
    assert findings["apps/recording.AIFF"] == {"media_file"}
    assert findings["apps/recording.CAF"] == {"media_file"}
    assert findings["apps/release.7Z"] == {"binary_artifact"}
    assert findings["apps/release.TAR"] == {"binary_artifact"}
    assert findings["apps/release.GZ"] == {"binary_artifact"}
    assert findings["apps/release.IPA"] == {"binary_artifact"}
    assert findings["apps/release.WHL"] == {"binary_artifact"}
    assert findings["apps/.Superpowers/note.md"] == {"private_path"}
    assert findings["apps/Transcripts/note.md"] == {"private_path"}


def test_audit_tree_rejects_sensitive_urls_and_platform_path_variants(
    tmp_path: Path,
) -> None:
    """Simplistic URL parsing would miss credentials, endpoints, and unsafe paths."""
    write_allowlist(tmp_path)
    write_file(
        tmp_path,
        "apps/unsafe_urls.py",
        "USERINFO = 'HTTPS://" + "alice:private-password@api.internal.invalid'\n"
        "IPV6 = 'https://" + "[2001:db8::dead]/v1'\n"
        "QUERY = 'https://" + "example.com/callback?token=private-token'\n"
        "HOST_QUERY = 'HTTPS://" + "service.invalid?mode=live,'\n"
        "HOST_FRAGMENT = 'https://" + "service.invalid#fragment.'\n"
        "BUCKET = 'S3://" + "private-exports-bucket/data'\n"
        "MAC_PATH = '/" + "USERS/alice/private'\n"
        "WINDOWS_PATH = 'C:" + "\\\\Users\\\\alice\\\\private'\n",
    )

    findings = audit_tree(tmp_path)
    rules = {finding.rule for finding in findings}

    assert {"credential", "deployment_endpoint", "bucket_identifier", "user_home_path"} <= rules
    assert all("alice" not in finding.evidence for finding in findings)
    assert all("private-password" not in finding.evidence for finding in findings)


def test_audit_tree_allows_documented_hosts_inside_url_variants(tmp_path: Path) -> None:
    """Rejecting safe loopback and RFC 5737 URLs would break public examples."""
    write_allowlist(tmp_path)
    write_file(
        tmp_path,
        "apps/safe_urls.py",
        "URLS = ['http://localhost?check=yes', 'https://127.0.0.1:8000/path', "
        "'http://[::1]/status', 'http://192.0.2.4?example=yes', "
        "'https://198.51.100.6/#reference', 'http://203.0.113.7/docs']\n",
    )

    assert audit_tree(tmp_path) == []


@pytest.mark.parametrize("separator", ["\\", "\\\\", "/"])
def test_audit_tree_rejects_each_windows_user_home_serialization(
    tmp_path: Path, separator: str
) -> None:
    """Missing an escaped Windows path form would expose a local identity."""
    write_allowlist(tmp_path)
    windows_path = "C:" + separator + "Users" + separator + "alice"
    write_file(tmp_path, "apps/windows_path.py", f"PATH = '{windows_path}'\n")

    assert findings_by_path(tmp_path)["apps/windows_path.py"] == {"user_home_path"}


@pytest.mark.parametrize(
    ("octets", "expected_rule"),
    [
        (("192", "0", "2", "8"), None),
        (("198", "51", "100", "8"), None),
        (("203", "0", "113", "8"), None),
        (("192", "0", "3", "8"), "deployment_endpoint"),
        (("198", "51", "42", "1"), "deployment_endpoint"),
        (("203", "0", "114", "8"), "deployment_endpoint"),
    ],
)
def test_audit_tree_applies_rfc5737_url_exceptions_to_exact_networks(
    tmp_path: Path, octets: tuple[str, str, str, str], expected_rule: str | None
) -> None:
    """Broad RFC 5737 exceptions would permit non-documentation addresses."""
    write_allowlist(tmp_path)
    host = ".".join(octets)
    write_file(tmp_path, "apps/ip_url.py", "URL = 'https://" + host + "/'\n")

    findings = audit_tree(tmp_path)

    if expected_rule is None:
        assert findings == []
    else:
        assert expected_rule in {finding.rule for finding in findings}


def test_ci_workflow_runs_every_required_blocking_command() -> None:
    """Removing a required CI command would leave unsafe changes unblocked."""
    workflow_path = REPOSITORY_ROOT / ".github/workflows/ci.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    run_commands = {
        step["run"]
        for job in jobs.values()
        for step in job.get("steps", [])
        if "run" in step
    }

    assert {"test", "public-tree-audit", "gitleaks", "dependency-review"} <= jobs.keys()
    assert {
        "uv run pytest",
        "uv run ruff check .",
        "python scripts/audit_public_tree.py .",
        "gitleaks git --redact --config .gitleaks.toml",
        "gitleaks git --redact --config .gitleaks-paths.toml",
    } <= run_commands


def test_gitleaks_domain_rule_blocks_protocol_and_bare_deployment_hosts() -> None:
    """Requiring a URL scheme would let bare deployment hosts evade Gitleaks."""
    protocol_rule = gitleaks_rule("non-example-domain")
    assignment_rule = gitleaks_rule("assigned-network-domain")
    bare_rule = gitleaks_rule("bare-deployment-domain")

    assert gitleaks_rule_findings(
        protocol_rule, "endpoint=https://" + "api.customer." + "com/v1"
    ) == [
        "https://" + "api.customer." + "com"
    ]
    assert gitleaks_rule_findings(
        assignment_rule, "HOST=customer." + "com"
    ) == ["customer." + "com"]
    assert gitleaks_rule_findings(
        assignment_rule, "BASE_URL=kb." + "customer.com"
    ) == ["kb." + "customer.com"]
    assert gitleaks_rule_findings(
        assignment_rule, "ORIGIN=tenant." + "museum"
    ) == ["tenant." + "museum"]
    assert gitleaks_rule_findings(bare_rule, "worker." + "customer.com") == [
        "worker." + "customer.com"
    ]
    assert gitleaks_rule_findings(bare_rule, "api." + "customer.com") == [
        "api." + "customer.com"
    ]
    combined_bare_hosts = (
        "HOST=customer." + "com\n"
        "BASE_URL=kb." + "customer.com\n"
        "worker." + "customer.com\n"
        "api." + "customer.com\n"
    )
    assert gitleaks_rule_findings(assignment_rule, combined_bare_hosts) == [
        "customer." + "com",
        "kb." + "customer.com",
    ]
    assert gitleaks_rule_findings(bare_rule, combined_bare_hosts) == [
        "worker." + "customer.com",
        "api." + "customer.com",
    ]

    for safe_host in (
        "https://" + "api.example.com/v1",
        "api." + "example.com",
        "https://files.pythonhosted.org/packages/",
        "https://" + "api.github.com/repos/",
        "api." + "github.com",
        "docs.python.org",
        "api.client.get",
        "HOST=example.com",
        "HOST=docs.python.org",
        "BASE_URL=files.pythonhosted.org",
    ):
        assert gitleaks_rule_findings(protocol_rule, safe_host) == []
        assert gitleaks_rule_findings(assignment_rule, safe_host) == []
        assert gitleaks_rule_findings(bare_rule, safe_host) == []


@pytest.mark.parametrize(
    ("content", "expected_secret"),
    [
        ("/" + "Users/alice/private", "/" + "Users/alice/private"),
        ("HOME=/" + "Users/bob/work", "/" + "Users/bob/work"),
        ("prefix (/" + "uSeRs/Carol/project)", "/" + "uSeRs/Carol/project"),
    ],
)
def test_gitleaks_macos_home_rule_captures_only_the_path(
    content: str, expected_secret: str
) -> None:
    """Requiring and capturing a delimiter would miss or over-redact home paths."""
    rule = gitleaks_rule("macos-user-home-path")

    assert gitleaks_rule_findings(rule, content) == [expected_secret]
