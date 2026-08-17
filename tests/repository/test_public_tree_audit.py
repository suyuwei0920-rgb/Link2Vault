from __future__ import annotations

import hashlib
import json
import re
import shutil
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
        allowlisted = False
        for allowlist in rule.get("allowlists", []):
            regex_target = allowlist.get("regexTarget", "secret")
            if regex_target == "secret":
                target = secret
            elif regex_target == "match":
                target = match.group(0)
            else:
                raise AssertionError(
                    f"unsupported test evaluator regex target: {regex_target}"
                )
            allowlisted = any(
                re.search(allow_regex, target)
                for allow_regex in allowlist.get("regexes", [])
            )
            if allowlisted:
                break
        if not allowlisted:
            findings.append(secret)
    return findings


def actual_gitleaks_findings(
    tmp_path: Path,
    files: dict[str, str],
    *,
    config_name: str = ".gitleaks.toml",
) -> list[dict[str, object]]:
    executable = shutil.which("gitleaks")
    if executable is None:
        pytest.skip("actual Gitleaks pressure tests require the pinned binary")

    source_root = tmp_path / "source"
    for relative_path, content in files.items():
        write_file(source_root, relative_path, content)

    report_path = tmp_path / "gitleaks-report.json"
    completed = subprocess.run(
        [
            executable,
            "dir",
            "--no-banner",
            "--redact",
            "--exit-code",
            "0",
            "--report-format",
            "json",
            "--report-path",
            str(report_path),
            "--config",
            str(REPOSITORY_ROOT / config_name),
            ".",
        ],
        cwd=source_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr

    findings = json.loads(report_path.read_text(encoding="utf-8"))
    assert isinstance(findings, list)
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


@pytest.mark.parametrize(
    ("content", "expected_rule", "expected_evidence"),
    [
        ("IP = '8" + ".8.8.8'\n", "ipv4_literal", "<ipv4-literal>"),
        ("HOME = '/" + "Users/alice/private'\n", "user_home_path", "<user-home-path>"),
        (
            "TOKEN = 'sk-" + "abcdefghijklmnop'\n",
            "credential",
            "sk-a...mnop",
        ),
        (
            "ENDPOINT = 'https://" + "api.customer-production.invalid/v1'\n",
            "deployment_endpoint",
            "<deployment-endpoint>",
        ),
        (
            "BUCKET = 's3://" + "customer-private-bucket/exports'\n",
            "bucket_identifier",
            "<bucket-identifier>",
        ),
    ],
)
def test_audit_tree_rejects_each_sensitive_source_value_independently(
    tmp_path: Path, content: str, expected_rule: str, expected_evidence: str
) -> None:
    """Each content detector must catch its own unsafe input without masking."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "apps/unsafe.py", content)

    findings = audit_tree(tmp_path)

    assert [(finding.rule, finding.evidence) for finding in findings] == [
        (expected_rule, expected_evidence)
    ]
    assert "abcdefghijklmnop" not in repr(findings)


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


def test_audit_tree_reads_unsafe_staged_blob_when_worktree_copy_is_safe(
    tmp_path: Path,
) -> None:
    """Reading only worktree bytes would let a safe edit mask a staged secret."""
    write_allowlist(tmp_path)
    staged_secret = "sk-" + "abcdefghijklmnop"
    write_file(tmp_path, "apps/config.py", f"TOKEN = '{staged_secret}'\n")
    initialize_git_repository(tmp_path)
    subprocess.run(
        ["git", "add", ".public-allowlist", "apps/config.py"],
        cwd=tmp_path,
        check=True,
    )
    write_file(tmp_path, "apps/config.py", "TOKEN = 'safe-placeholder'\n")

    findings = [
        finding for finding in audit_tree(tmp_path) if finding.path == "apps/config.py"
    ]

    assert [(finding.rule, finding.evidence) for finding in findings] == [
        ("credential", "sk-a...mnop")
    ]
    assert staged_secret not in repr(findings)


def test_audit_tree_reads_unsafe_worktree_copy_when_staged_blob_is_safe(
    tmp_path: Path,
) -> None:
    """Scanning only the index would miss unsafe unstaged content."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "apps/config.py", "TOKEN = 'safe-placeholder'\n")
    initialize_git_repository(tmp_path)
    subprocess.run(
        ["git", "add", ".public-allowlist", "apps/config.py"],
        cwd=tmp_path,
        check=True,
    )
    worktree_secret = "sk-" + "qrstuvwxyzABCDEF"
    write_file(tmp_path, "apps/config.py", f"TOKEN = '{worktree_secret}'\n")

    findings = [
        finding for finding in audit_tree(tmp_path) if finding.path == "apps/config.py"
    ]

    assert [(finding.rule, finding.evidence) for finding in findings] == [
        ("credential", "sk-q...CDEF")
    ]
    assert worktree_secret not in repr(findings)


def test_machine_allowlist_accepts_packages_and_only_docker_deployments(
    tmp_path: Path,
) -> None:
    """A broad deploy entry or missing packages entry would violate policy."""
    write_file(
        tmp_path,
        ".public-allowlist",
        (REPOSITORY_ROOT / ".public-allowlist").read_text(encoding="utf-8"),
    )
    write_file(tmp_path, "packages/provider/__init__.py", "PUBLIC = True\n")
    write_file(tmp_path, "deploy/docker/compose.override.yml", "services: {}\n")
    write_file(tmp_path, "deploy/production/customer.yml", "services: {}\n")

    findings = findings_by_path(tmp_path)

    assert "packages/provider/__init__.py" not in findings
    assert "deploy/docker/compose.override.yml" not in findings
    assert findings["deploy/production/customer.yml"] == {"not_allowlisted"}


def test_audit_tree_intrinsically_rejects_force_added_envrc(tmp_path: Path) -> None:
    """Allowlist membership must never override the .env* deny rule."""
    write_allowlist(tmp_path)
    write_file(tmp_path, ".gitignore", ".env*\n")
    write_file(tmp_path, "apps/.envrc", "export SAFE_PLACEHOLDER=yes\n")
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-f", "apps/.envrc"], cwd=tmp_path, check=True)

    assert findings_by_path(tmp_path)["apps/.envrc"] == {"environment_file"}


def test_audit_tree_intrinsically_rejects_force_added_recordings_component(
    tmp_path: Path,
) -> None:
    """Case variants of recordings directories must remain intrinsically private."""
    write_allowlist(tmp_path)
    write_file(tmp_path, ".gitignore", "apps/ReCoRdInGs/\n")
    write_file(tmp_path, "apps/ReCoRdInGs/notes.txt", "private recording notes\n")
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "add", "-f", "apps/ReCoRdInGs/notes.txt"],
        cwd=tmp_path,
        check=True,
    )

    assert findings_by_path(tmp_path)["apps/ReCoRdInGs/notes.txt"] == {
        "private_path"
    }


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


def test_nested_git_discovery_prunes_ignored_parents_but_keeps_public_paths(
    tmp_path: Path,
) -> None:
    """Ruling A excludes ignored local trees without hiding public nested Git."""
    write_allowlist(tmp_path)
    write_file(tmp_path, ".gitignore", "scratch/\n")
    write_file(tmp_path, "scratch/donor/.git/config", "[core]\n")
    write_file(tmp_path, "apps/embedded/tracked.txt", "public marker\n")
    write_file(tmp_path, "apps/embedded/.git/config", "[core]\n")
    initialize_git_repository(tmp_path)
    subprocess.run(
        ["git", "add", ".public-allowlist", ".gitignore", "apps/embedded/tracked.txt"],
        cwd=tmp_path,
        check=True,
    )

    nested_git_paths = {
        finding.path for finding in audit_tree(tmp_path) if finding.rule == "nested_git"
    }

    assert nested_git_paths == {"apps/embedded/.git"}


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


@pytest.mark.parametrize(
    ("content", "expected_rules"),
    [
        (
            "USERINFO = 'HTTPS://"
            + "alice:private-password@api.internal.invalid'\n",
            {"credential", "deployment_endpoint"},
        ),
        (
            "IPV6 = 'https://" + "[2001:db8::dead]/v1'\n",
            {"deployment_endpoint"},
        ),
        (
            "QUERY = 'https://" + "example.com/callback?token=private-token'\n",
            {"credential"},
        ),
        (
            "HOST_QUERY = 'HTTPS://" + "service.invalid?mode=live,'\n",
            {"deployment_endpoint"},
        ),
        (
            "HOST_FRAGMENT = 'https://" + "service.invalid#fragment.'\n",
            {"deployment_endpoint"},
        ),
        (
            "BUCKET = 'S3://" + "private-exports-bucket/data'\n",
            {"bucket_identifier"},
        ),
        ("MAC_PATH = '/" + "USERS/alice/private'\n", {"user_home_path"}),
        (
            "WINDOWS_PATH = 'C:" + "\\\\Users\\\\alice\\\\private'\n",
            {"user_home_path"},
        ),
    ],
)
def test_audit_tree_rejects_each_url_and_platform_path_variant_independently(
    tmp_path: Path, content: str, expected_rules: set[str]
) -> None:
    """Each URL/path variant must trigger its own detector without masking."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "apps/unsafe_urls.py", content)

    findings = audit_tree(tmp_path)
    rules = {finding.rule for finding in findings}

    assert rules == expected_rules
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


def test_ci_workflow_enforces_job_placement_and_security_contracts() -> None:
    """Moving or weakening a gate would leave unsafe changes unblocked."""
    workflow_path = REPOSITORY_ROOT / ".github/workflows/ci.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    required_jobs = {
        "test",
        "public-tree-audit",
        "gitleaks",
        "docker-contract",
        "dependency-review",
    }

    assert required_jobs <= jobs.keys()
    assert workflow["permissions"] == {"contents": "read"}
    assert all("permissions" not in job for job in jobs.values())
    assert all(
        "continue-on-error" not in step
        for job in jobs.values()
        for step in job.get("steps", [])
    )
    assert all("continue-on-error" not in job for job in jobs.values())

    commands_by_job = {
        job_name: {
            step["run"] for step in job["steps"] if isinstance(step.get("run"), str)
        }
        for job_name, job in jobs.items()
    }
    assert {"uv run pytest", "uv run ruff check ."} <= commands_by_job["test"]
    assert "uv run python scripts/audit_public_tree.py ." in commands_by_job[
        "public-tree-audit"
    ]
    assert {
        "uv run pytest tests/repository/test_public_tree_audit.py -k actual_gitleaks -v",
        "gitleaks git --redact --log-opts=HEAD --config .gitleaks.toml",
        "gitleaks git --redact --log-opts=HEAD --config .gitleaks-paths.toml",
    } <= commands_by_job["gitleaks"]
    assert {
        "docker version",
        "docker compose version",
        "docker info",
        "uv run pytest tests/deploy/test_compose_contract.py -v",
    } <= commands_by_job["docker-contract"]

    gitleaks_checkout = next(
        step
        for step in jobs["gitleaks"]["steps"]
        if step.get("uses") == "actions/checkout@v7"
    )
    assert gitleaks_checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    assert jobs["dependency-review"]["if"] == "github.event_name == 'pull_request'"

    allowed_action_pins = {
        "actions/checkout@v7",
        "actions/setup-python@v6",
        "astral-sh/setup-uv@v9",
        "actions/dependency-review-action@v5",
    }
    used_actions = {
        step["uses"]
        for job in jobs.values()
        for step in job.get("steps", [])
        if "uses" in step
    }
    assert used_actions <= allowed_action_pins
    assert all(
        "@" in action and not action.endswith(("@main", "@master"))
        for action in used_actions
    )

    checkout_steps = [
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if step.get("uses") == "actions/checkout@v7"
    ]
    assert checkout_steps
    assert all(step["with"]["persist-credentials"] is False for step in checkout_steps)
    setup_python_steps = [
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if step.get("uses") == "actions/setup-python@v6"
    ]
    assert setup_python_steps
    assert all(step["with"] == {"python-version": "3.12"} for step in setup_python_steps)
    setup_uv_steps = [
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if step.get("uses") == "astral-sh/setup-uv@v9"
    ]
    assert setup_uv_steps
    assert all(
        step["with"] == {"version": "0.12.1", "enable-cache": True}
        for step in setup_uv_steps
    )
    install_gitleaks = next(
        step
        for step in jobs["gitleaks"]["steps"]
        if step.get("name") == "Install checksum-verified Gitleaks"
    )["run"]
    assert "v8.30.1" in install_gitleaks
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in install_gitleaks


def test_packaging_declares_bounded_backend_and_direct_yaml_dependency() -> None:
    """Unbounded build tooling or a transitive YAML import breaks reproducibility."""
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as project_file:
        project = tomllib.load(project_file)

    assert project["build-system"] == {
        "requires": ["hatchling==1.32.0"],
        "build-backend": "hatchling.build",
    }
    assert "pyyaml>=6,<7" in project["dependency-groups"]["dev"]


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
    compound_host = "HOST=settings." + "host,api." + "customer.com"
    assert gitleaks_rule_findings(assignment_rule, compound_host) == []
    assert gitleaks_rule_findings(bare_rule, compound_host) == [
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
        "HOST=example.com",
        "HOST=docs.python.org",
        "BASE_URL=files.pythonhosted.org",
    ):
        assert gitleaks_rule_findings(protocol_rule, safe_host) == []
        assert gitleaks_rule_findings(assignment_rule, safe_host) == []
        assert gitleaks_rule_findings(bare_rule, safe_host) == []

    source_member = "api.client.get"
    assert gitleaks_rule_findings(protocol_rule, source_member) == []
    assert gitleaks_rule_findings(assignment_rule, source_member) == []


@pytest.mark.parametrize(
    ("content", "expected_secret"),
    [
        ("KB_HOST=kb." + "customer.com", "kb." + "customer.com"),
        ("REDIS_HOST: redis." + "customer.com", "redis." + "customer.com"),
        (
            "SERVICE_ENDPOINT=service." + "customer.com",
            "service." + "customer.com",
        ),
        (
            "PUBLIC_ORIGIN: public." + "customer.com",
            "public." + "customer.com",
        ),
        (
            '"API_BASE_URL": "api.' + 'customer.com"',
            "api." + "customer.com",
        ),
    ],
)
def test_gitleaks_assignment_rule_supports_composite_keys(
    content: str, expected_secret: str
) -> None:
    """Requiring exact key names would let common composite keys evade scanning."""
    assignment_rule = gitleaks_rule("assigned-network-domain")
    bare_rule = gitleaks_rule("bare-deployment-domain")

    assert gitleaks_rule_findings(assignment_rule, content) == [expected_secret]
    assert gitleaks_rule_findings(bare_rule, content) == []


@pytest.mark.parametrize(
    ("content", "expected_secret"),
    [
        ("DOMAIN=customer." + "com", "customer." + "com"),
        ("PUBLIC_DOMAIN=customer." + "com", "customer." + "com"),
        ("customer-domain: customer." + "com", "customer." + "com"),
    ],
)
def test_gitleaks_assignment_rule_supports_strict_domain_keys(
    content: str, expected_secret: str
) -> None:
    """Omitting exact/composite DOMAIN keys would miss common deployment config."""
    rule = gitleaks_rule("assigned-domain-name")

    assert gitleaks_rule_findings(rule, content) == [expected_secret]


def test_gitleaks_assignment_rule_does_not_match_domain_name_substrings() -> None:
    """DOMAIN support must not turn arbitrary source identifiers into secrets."""
    rule = gitleaks_rule("assigned-domain-name")

    for source_expression in (
        "RANDOMDOMAIN=customer." + "com",
        "SUBDOMAIN=customer." + "com",
        "object.domain=customer." + "com",
    ):
        assert gitleaks_rule_findings(rule, source_expression) == []


def test_gitleaks_assignment_rule_has_narrow_source_chain_exceptions() -> None:
    """Safe source chains need exact exceptions without weakening domain detection."""
    rule = gitleaks_rule("assigned-network-domain")

    for safe_assignment in (
        "PUBLIC_ORIGIN=location." + "origin",
        "PUBLIC_ORIGIN=window." + "location.origin",
        "SERVICE_SERVER=config." + "server",
        "KB_HOST=settings." + "host",
        "PUBLIC_DOMAIN=settings." + "domain",
        "PUBLIC_ORIGIN = window." + "location.origin;",
        "SERVICE_SERVER: config." + "server,",
        "configure(KB_HOST=settings." + "host)",
        "GHOST=customer." + "com",
        "LOCALHOST=customer." + "com",
    ):
        assert gitleaks_rule_findings(rule, safe_assignment) == []

    for unsafe_literal, expected_secret in (
        ('KB_HOST="settings.' + 'host"', "settings.host"),
        ("SERVICE_SERVER='config." + "server'", "config.server"),
        ('"KB_HOST=settings.' + 'host"', "settings.host"),
        ("'SERVICE_SERVER=config." + "server'", "config.server"),
        ("KB_HOST=settings." + "host/v1", "settings.host"),
        ("SERVICE_SERVER=config." + "server?mode=live", "config.server"),
    ):
        assert gitleaks_rule_findings(rule, unsafe_literal) == [expected_secret]


def test_actual_gitleaks_blocks_indented_hosts_and_non_source_literals(
    tmp_path: Path,
) -> None:
    """Indentation, quotes, or literal suffixes must not hide deployment domains."""
    unsafe_domain = "customer." + "com"
    content = (
        "  worker."
        + unsafe_domain
        + "\nsection:\n    api."
        + unsafe_domain
        + "\n  REDIS_HOST: redis."
        + unsafe_domain
        + '\nKB_HOST="settings.'
        + 'host"\nSERVICE_SERVER=\'config.'
        + "server'\n\"KB_HOST=settings."
        + 'host"\n\'SERVICE_SERVER=config.'
        + "server'\nKB_HOST=settings.host/v1"
        + "\nSERVICE_SERVER=config.server?mode=live"
        + "\nHOST=settings.host,api."
        + unsafe_domain
        + "\nHOST="
        + unsafe_domain
        + "\nBASE_URL=kb."
        + unsafe_domain
        + "\nORIGIN=tenant."
        + "museum\nworker."
        + unsafe_domain
        + "\napi."
        + unsafe_domain
        + "\nENDPOINT=https://"
        + "api."
        + unsafe_domain
        + "/v1\n"
    )

    findings = actual_gitleaks_findings(tmp_path, {"pressure.txt": content})
    owned_findings = [
        finding
        for finding in findings
        if finding["RuleID"]
        not in {"bare-apex-domain", "adjacent-bare-apex-domain"}
    ]

    assert sorted(
        (finding["StartLine"], finding["RuleID"]) for finding in owned_findings
    ) == [
        (1, "bare-deployment-domain"),
        (3, "bare-deployment-domain"),
        (4, "assigned-network-domain"),
        (5, "assigned-network-domain"),
        (6, "assigned-network-domain"),
        (7, "assigned-network-domain"),
        (8, "assigned-network-domain"),
        (9, "assigned-network-domain"),
        (10, "assigned-network-domain"),
        (11, "bare-deployment-domain"),
        (12, "assigned-network-domain"),
        (13, "assigned-network-domain"),
        (14, "assigned-network-domain"),
        (15, "bare-deployment-domain"),
        (16, "bare-deployment-domain"),
        (17, "non-example-domain"),
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    assert unsafe_domain not in json.dumps(findings)


def test_actual_gitleaks_allows_unquoted_source_chains_and_public_hosts(
    tmp_path: Path,
) -> None:
    """Source expressions and approved public hosts must remain false-positive safe."""
    source_content = (
        "PUBLIC_ORIGIN=location."
        + "origin\nPUBLIC_ORIGIN=window."
        + "location.origin\nSERVICE_SERVER=config."
        + "server\nKB_HOST=settings."
        + "host\nPUBLIC_ORIGIN = window."
        + "location.origin;\nSERVICE_SERVER: config."
        + "server,\nconfigure(KB_HOST=settings."
        + "host)\napi.client.get\nGHOST=customer."
        + "com\nLOCALHOST=customer."
        + "com\n"
    )
    public_host_content = (
        "HOST=example.com\n"
        "HOST=docs.python.org\n"
        "BASE_URL=files.pythonhosted.org\n"
        "api.github.com\n"
        "https://docs.python.org/\n"
    )

    assert actual_gitleaks_findings(
        tmp_path,
        {
            "apps/api/source.py": source_content,
            "docs/public-hosts.txt": public_host_content,
        },
    ) == []


def test_actual_gitleaks_blocks_domain_keys_and_docs_config_apex_domains(
    tmp_path: Path,
) -> None:
    """Apex domains must be caught in strict keys, documentation, and config."""
    apex = "customer." + "com"
    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "apps/api/settings.py": (
                "DOMAIN=" + apex + "\nPUBLIC_DOMAIN=portal." + "example.invalid\n"
            ),
            "apps/api/prose.py": "EXAMPLE = 'The customer." + "com format'\n",
            "docs/deployment.md": "Production tenant: " + apex + "\n",
            "deploy/docker/settings.toml": "site = \"" + apex + "\"\n",
        },
    )

    assert sorted(
        (finding["File"], finding["StartLine"], finding["RuleID"])
        for finding in findings
    ) == [
        ("apps/api/settings.py", 1, "assigned-domain-name"),
        ("deploy/docker/settings.toml", 1, "bare-apex-domain"),
        ("docs/deployment.md", 1, "bare-apex-domain"),
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    assert apex not in json.dumps(findings)


@pytest.mark.parametrize(
    (
        "relative_path",
        "content_prefix",
        "unsafe_domain",
        "content_suffix",
        "expected_rule",
    ),
    [
        (
            "README.md",
            "Production host: ",
            "customer." + "finance",
            "\n",
            "bare-apex-domain",
        ),
        (
            "SECURITY.md",
            "Report incidents for ",
            "portal.customer." + "technology",
            "\n",
            "bare-apex-domain",
        ),
        (
            "NOTICE",
            "Service operated at ",
            "customer." + "solutions",
            "\n",
            "bare-apex-domain",
        ),
        (
            "THIRD_PARTY_NOTICES",
            "Mirror: ",
            "customer." + "company",
            "\n",
            "bare-apex-domain",
        ),
        (
            "THIRD_PARTY_NOTICES.md",
            "Mirror: ",
            "customer." + "company",
            "\n",
            "bare-apex-domain",
        ),
        (
            "docs/install.md",
            "Install from ",
            "customer." + "museum",
            "\n",
            "bare-apex-domain",
        ),
        (
            "docs/config.toml",
            "Service: ",
            "service.customer." + "international",
            "\n",
            "bare-apex-domain",
        ),
        (
            "notes/runbook.rst",
            "Fail over to ",
            "customer." + "finance",
            "\n",
            "bare-apex-domain",
        ),
        (
            "config/example.yaml",
            "DOMAIN=",
            "customer." + "finance",
            "\n",
            "assigned-domain-name",
        ),
        (
            "config/example.json",
            '"PUBLIC_DOMAIN": "',
            "tenant." + "xn--fiqs8s",
            '"\n',
            "assigned-domain-name",
        ),
    ],
    ids=[
        "readme",
        "security",
        "notice",
        "third-party-notices",
        "third-party-notices-markdown",
        "docs-markdown",
        "docs-config",
        "document-extension",
        "domain-assignment",
        "punycode-assignment",
    ],
)
def test_actual_gitleaks_apex_domain_blocks_root_docs_and_arbitrary_tlds(
    tmp_path: Path,
    relative_path: str,
    content_prefix: str,
    unsafe_domain: str,
    content_suffix: str,
    expected_rule: str,
) -> None:
    """Finite TLD/path lists must not let one public-file domain evade scanning."""
    findings = actual_gitleaks_findings(
        tmp_path,
        {relative_path: content_prefix + unsafe_domain + content_suffix},
    )

    intended_findings = [
        finding for finding in findings if finding["RuleID"] == expected_rule
    ]
    assert len(intended_findings) == 1
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    assert unsafe_domain not in json.dumps(findings)


def test_actual_gitleaks_apex_domain_handles_case_quotes_punctuation_and_many_per_line(
    tmp_path: Path,
) -> None:
    """Case, punctuation, and neighboring findings must not truncate detection."""
    unsafe_domains = [
        "Customer." + "FINANCE",
        "portal.Customer." + "Technology",
        "tenant." + "solutions",
    ]
    content = (
        'Hosts: "'
        + unsafe_domains[0]
        + '", '
        + unsafe_domains[1]
        + "; "
        + unsafe_domains[2]
        + '".\n'
    )

    findings = actual_gitleaks_findings(tmp_path, {"docs/hosts.md": content})
    apex_findings = [
        finding for finding in findings if finding["RuleID"] == "bare-apex-domain"
    ]

    assert len(apex_findings) == len(unsafe_domains)
    assert all(finding["Secret"] == "REDACTED" for finding in apex_findings)
    report = json.dumps(findings)
    assert all(unsafe_domain not in report for unsafe_domain in unsafe_domains)


ADJACENT_DOMAIN_CASES = (
    pytest.param(
        "docs/adjacent.md",
        "customer." + "finance",
        "portal.customer." + "technology",
        "bare-apex-domain",
        "adjacent-bare-apex-domain",
        id="bare-prose",
    ),
    pytest.param(
        "apps/domain-settings.py",
        "DOMAIN=customer." + "finance",
        "PUBLIC_DOMAIN=portal." + "technology",
        "assigned-domain-name",
        "adjacent-assigned-domain-name",
        id="domain-assignments",
    ),
    pytest.param(
        "apps/network-settings.py",
        "HOST=api.customer." + "com",
        "ORIGIN=portal.customer." + "com",
        "assigned-network-domain",
        "adjacent-assigned-network-domain",
        id="network-assignments",
    ),
)


@pytest.mark.parametrize(
    ("path", "first", "second", "owning_rule", "companion_rule"),
    ADJACENT_DOMAIN_CASES,
)
@pytest.mark.parametrize(
    "separator", [" ", ",", ";"], ids=["space", "comma", "semicolon"]
)
def test_actual_gitleaks_apex_domain_reports_exactly_two_with_one_separator(
    tmp_path: Path,
    path: str,
    first: str,
    second: str,
    owning_rule: str,
    companion_rule: str,
    separator: str,
) -> None:
    """The companion owns only the second value hidden by one separator."""
    findings = actual_gitleaks_findings(
        tmp_path,
        {path: first + separator + second + "\n"},
    )

    assert len(findings) == 2
    assert {finding["RuleID"] for finding in findings} == {
        owning_rule,
        companion_rule,
    }
    assert len(
        {
            (
                finding["File"],
                finding["RuleID"],
                finding["StartLine"],
                finding["StartColumn"],
                finding["EndLine"],
                finding["EndColumn"],
            )
            for finding in findings
        }
    ) == len(findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert first.split("=", 1)[-1] not in report
    assert second.split("=", 1)[-1] not in report


@pytest.mark.parametrize(
    ("path", "first", "second", "owning_rule", "companion_rule"),
    ADJACENT_DOMAIN_CASES,
)
@pytest.mark.parametrize(
    "separator",
    [", ", "; ", "  ", "\t\t"],
    ids=["comma-space", "semicolon-space", "repeated-spaces", "repeated-tabs"],
)
def test_actual_gitleaks_apex_domain_avoids_companion_duplicates(
    tmp_path: Path,
    path: str,
    first: str,
    second: str,
    owning_rule: str,
    companion_rule: str,
    separator: str,
) -> None:
    """Multiple separators leave both values visible to the owning rule alone."""
    findings = actual_gitleaks_findings(
        tmp_path,
        {path: first + separator + second + "\n"},
    )

    assert len(findings) == 2
    assert {finding["RuleID"] for finding in findings} == {owning_rule}
    assert companion_rule not in {finding["RuleID"] for finding in findings}
    assert len(
        {
            (
                finding["File"],
                finding["RuleID"],
                finding["StartLine"],
                finding["StartColumn"],
                finding["EndLine"],
                finding["EndColumn"],
            )
            for finding in findings
        }
    ) == len(findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert first.split("=", 1)[-1] not in report
    assert second.split("=", 1)[-1] not in report


def test_actual_gitleaks_apex_domain_deployment_prefix_supports_arbitrary_tlds(
    tmp_path: Path,
) -> None:
    """Deployment-style prose domains must not retain a finite TLD list."""
    unsafe_domains = [
        "api.customer." + "finance",
        "worker.customer." + "xn--fiqs8s",
    ]

    findings = actual_gitleaks_findings(
        tmp_path,
        {"docs/deployment-hosts.txt": "\n".join(unsafe_domains) + "\n"},
    )
    deployment_findings = [
        finding
        for finding in findings
        if finding["RuleID"]
        in {"bare-deployment-domain", "bare-deployment-domain-arbitrary"}
    ]

    assert sorted(
        (finding["StartLine"], finding["RuleID"])
        for finding in deployment_findings
    ) == [
        (1, "bare-deployment-domain-arbitrary"),
        (2, "bare-deployment-domain"),
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in deployment_findings)
    report = json.dumps(findings)
    assert all(unsafe_domain not in report for unsafe_domain in unsafe_domains)


def test_actual_gitleaks_apex_domain_handles_quoted_and_unquoted_assignments(
    tmp_path: Path,
) -> None:
    """Assignment delimiters must not become part of the captured domain secret."""
    unsafe_domains = [
        "customer." + "finance",
        "Portal.Customer." + "Technology",
        "tenant." + "solutions",
    ]
    content = (
        "DOMAIN="
        + unsafe_domains[0]
        + '\n"PUBLIC_DOMAIN": "'
        + unsafe_domains[1]
        + '",\ntenant-domain = \''
        + unsafe_domains[2]
        + "'\n"
    )

    findings = actual_gitleaks_findings(tmp_path, {"config/domains.yaml": content})
    assignment_findings = [
        finding
        for finding in findings
        if finding["RuleID"] == "assigned-domain-name"
    ]

    assert [finding["StartLine"] for finding in assignment_findings] == [1, 2, 3]
    assert all(finding["Secret"] == "REDACTED" for finding in assignment_findings)
    report = json.dumps(findings)
    assert all(unsafe_domain not in report for unsafe_domain in unsafe_domains)


def test_actual_gitleaks_apex_domain_allows_reserved_and_canonical_hosts(
    tmp_path: Path,
) -> None:
    """Narrow public/reserved exceptions must remain usable in documentation."""
    documented_hosts = [
        "example.com",
        "example.test",
        "service.invalid",
        "tenant.localhost",
        "localhost",
        "docs.python.org",
        "pypi.org",
        "files.pythonhosted.org",
        "github.com",
        "api.github.com",
        "www.apache.org",
        "docs.docker.com",
        "astral.sh",
    ]

    assert actual_gitleaks_findings(
        tmp_path,
        {
            "docs/public-hosts.md": "\n".join(documented_hosts) + "\n",
            "apps/safe-domain-assignments.py": (
                "DOMAIN=example.test\n"
                "PUBLIC_DOMAIN=service.invalid\n"
                "tenant-domain=tenant.localhost\n"
                "HOST=docs.docker.com\n"
                "PUBLIC_DOMAIN=astral.sh\n"
            ),
        },
    ) == []


def test_actual_gitleaks_apex_domain_allows_reviewed_file_and_member_identifiers(
    tmp_path: Path,
) -> None:
    """Known public filenames and config member chains are not deployment domains."""
    assert actual_gitleaks_findings(
        tmp_path,
        {
            "README.md": (
                "Before contributing files, read [the public/private boundary]"
                "(docs/public-boundary.md). In particular:\n"
                "Please read [SECURITY.md](SECURITY.md) before reporting a "
                "vulnerability or contributing security-sensitive changes.\n"
                "commands, see the [Docker installation guide]"
                "(docs/install/docker.md).\n"
            ),
            "THIRD_PARTY_NOTICES.md": (
                "`pyproject.toml`; their transitive dependencies remain governed "
                "by their own\n"
                "| Dependency | Direct use | Declared version | Resolved version "
                "in `uv.lock` | License | Source |\n"
            ),
            "pyproject.toml": (
                'build-backend = "hatchling.build"\n'
                'readme = "README.md"\n'
                "[tool.hatch.build.targets.wheel]\n"
                "[tool.pytest.ini_options]\n"
                "[tool.ruff]\n"
            ),
            "apps/api/Dockerfile": (
                "COPY pyproject.toml uv.lock README.md ./\n"
                'CMD ["uvicorn", "link2vault.main:create_app", "--factory", '
                '"--host", "0.0.0.0", "--port", "8000", '
                '"--no-access-log"]\n'
            ),
            "deploy/docker/Caddyfile.example": (
                "\t\t@oversized expression "
                "`{http.request.header.Content-Length} != \"\" && "
                "int({http.request.header.Content-Length}) > "
                "{$LINK2VAULT_MAX_UPLOAD_MB:1024} * 1000 * 1000`\n"
            ),
            "deploy/docker/compose.yml": (
                "      - link2vault.main:create_app\n"
                "          import json, urllib.request;\n"
                "          data=json.load(urllib.request.urlopen("
                "'http://127.0.0.1:8000/healthz'));\n"
                "      - import signal; signal.pause()\n"
            ),
            ".github/workflows/ci.yml": (
                "if: github.event_name == 'pull_request'\n"
            ),
            ".gitleaks-paths.toml": "[[rules.allowlists]]\n",
        },
    ) == []


def test_actual_gitleaks_apex_domain_does_not_scan_source_member_chains_or_prose(
    tmp_path: Path,
) -> None:
    """Expanding prose coverage to source files would create member-chain noise."""
    prose_domain = "customer." + "finance"
    source_content = (
        "client = api.client.get\n"
        "origin = location."
        + "origin\n"
        + "message = 'Deploy "
        + prose_domain
        + "'\n"
    )

    assert actual_gitleaks_findings(
        tmp_path,
        {
            "apps/source.py": source_content,
            "apps/source.ts": source_content,
            "apps/source.tsx": source_content,
            "apps/Source.java": source_content,
        },
    ) == []


def test_actual_gitleaks_apex_domain_excludes_source_extensions_under_docs(
    tmp_path: Path,
) -> None:
    """The docs directory must not override source-extension prose exclusions."""
    prose_domain = "customer." + "finance"
    source_content = (
        "client = api.client.get\n"
        "origin = location."
        + "origin\n"
        + "message = 'Deploy "
        + prose_domain
        + "'\n"
    )

    assert actual_gitleaks_findings(
        tmp_path,
        {
            "docs/example.py": source_content,
            "docs/example.ts": source_content,
            "docs/example.tsx": source_content,
            "docs/Example.java": source_content,
        },
    ) == []


def test_actual_gitleaks_apex_domain_scans_unlisted_extensions_under_docs(
    tmp_path: Path,
) -> None:
    """Excluding docs source files must not narrow the required docs/** scope."""
    unsafe_domains = [
        "customer." + "finance",
        "portal.customer." + "technology",
    ]

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "docs/hosts.csv": "Deploy " + unsafe_domains[0] + " now\n",
            "docs/hosts.xhtml": "Deploy " + unsafe_domains[1] + " now\n",
        },
    )

    assert sorted(
        (finding["File"], finding["RuleID"]) for finding in findings
    ) == [
        ("docs/hosts.csv", "bare-apex-domain"),
        ("docs/hosts.xhtml", "bare-apex-domain"),
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(unsafe_domain not in report for unsafe_domain in unsafe_domains)


def test_actual_gitleaks_apex_domain_keeps_explicit_rules_in_docs_source_files(
    tmp_path: Path,
) -> None:
    """Source prose exclusion must not disable URL, assignment, or deployment rules."""
    arbitrary_domain = "customer." + "finance"
    deployment_domain = "api.customer." + "com"
    content = (
        "DOMAIN="
        + arbitrary_domain
        + "\nHOST="
        + deployment_domain
        + "\nURL=https://"
        + deployment_domain
        + "/v1\n"
        + deployment_domain
        + "\n"
    )

    findings = actual_gitleaks_findings(tmp_path, {"docs/explicit.py": content})

    assert sorted(
        (finding["StartLine"], finding["RuleID"]) for finding in findings
    ) == [
        (1, "assigned-domain-name"),
        (2, "assigned-network-domain"),
        (3, "non-example-domain"),
        (4, "bare-deployment-domain"),
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in findings)


def test_actual_gitleaks_apex_domain_restores_source_deployment_prefix_rule(
    tmp_path: Path,
) -> None:
    """Path-scoping broad prose must not disable narrow source deployment hosts."""
    deployment_domain = "api.customer." + "com"

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "apps/source.py": deployment_domain + "\napi.client.get\n",
        },
    )

    assert len(findings) == 1
    assert findings[0]["RuleID"] == "bare-deployment-domain"
    assert findings[0]["Secret"] == "REDACTED"
    assert deployment_domain not in json.dumps(findings)


@pytest.mark.parametrize(
    "host_value",
    [
        "README.md",
        "settings.toml",
        "link2vault.main",
        "urllib.request",
    ],
)
def test_actual_gitleaks_apex_domain_context_allowlists_do_not_hide_host_values(
    tmp_path: Path, host_value: str
) -> None:
    """Safe-context exceptions must not suppress the same token as a host value."""
    findings = actual_gitleaks_findings(
        tmp_path,
        {"README.md": "Production host: " + host_value + "\n"},
    )
    bare_findings = [
        finding for finding in findings if finding["RuleID"] == "bare-apex-domain"
    ]

    assert len(bare_findings) == 1
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    assert all(host_value not in str(finding["Match"]) for finding in findings)


def test_actual_gitleaks_apex_domain_requires_valid_dns_label_boundaries(
    tmp_path: Path,
) -> None:
    """Invalid labels and overlong TLDs must not yield truncated domain findings."""
    invalid_domains = [
        "-customer." + "finance",
        "customer-." + "finance",
        "customer." + "f",
        "customer." + ("a" * 64),
        "customer." + "xn--a",
        "customer." + "xn--ab-",
    ]

    assert actual_gitleaks_findings(
        tmp_path,
        {"docs/invalid-domains.md": "\n".join(invalid_domains) + "\n"},
    ) == []


@pytest.mark.parametrize(
    ("bare_separator", "assignment_separator", "expected_rules"),
    [
        pytest.param(
            " ",
            ";",
            {
                "adjacent-assigned-network-domain",
                "adjacent-assigned-domain-name",
                "adjacent-bare-apex-domain",
                "assigned-network-domain",
                "assigned-domain-name",
                "bare-apex-domain",
            },
            id="single-separator-companions",
        ),
        pytest.param(
            ", ",
            "; ",
            {
                "assigned-domain-name",
                "assigned-network-domain",
                "bare-apex-domain",
            },
            id="multiple-separator-owning-rules",
        ),
    ],
)
def test_actual_gitleaks_apex_domain_adjacent_rules_preserve_dummy_and_path(
    tmp_path: Path,
    bare_separator: str,
    assignment_separator: str,
    expected_rules: set[str],
) -> None:
    """New adjacent rules retain the fixture-path AND DUMMY_ contract."""
    domains = ["customer." + "finance", "portal." + "technology"]
    dummy_domains = ["DUMMY_" + domain for domain in domains]

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "tests/fixtures-synthetic/safe.md": (
                bare_separator.join(dummy_domains) + "\n"
            ),
            "tests/fixtures-synthetic/non-dummy.md": (
                bare_separator.join(domains) + "\n"
            ),
            "docs/dummy-outside-fixtures.md": (
                bare_separator.join(dummy_domains) + "\n"
            ),
            "tests/fixtures-synthetic/safe.py": (
                "DOMAIN="
                + dummy_domains[0]
                + assignment_separator
                + "PUBLIC_DOMAIN="
                + dummy_domains[1]
                + "\n"
            ),
            "tests/fixtures-synthetic/non-dummy.py": (
                "DOMAIN="
                + domains[0]
                + assignment_separator
                + "PUBLIC_DOMAIN="
                + domains[1]
                + "\n"
            ),
            "apps/dummy-outside-fixtures.py": (
                "DOMAIN="
                + dummy_domains[0]
                + assignment_separator
                + "PUBLIC_DOMAIN="
                + dummy_domains[1]
                + "\n"
            ),
            "tests/fixtures-synthetic/safe-network.py": (
                "HOST="
                + dummy_domains[0]
                + assignment_separator
                + "ORIGIN="
                + dummy_domains[1]
                + "\n"
            ),
            "tests/fixtures-synthetic/non-dummy-network.py": (
                "HOST="
                + domains[0]
                + assignment_separator
                + "ORIGIN="
                + domains[1]
                + "\n"
            ),
            "apps/dummy-network-outside-fixtures.py": (
                "HOST="
                + dummy_domains[0]
                + assignment_separator
                + "ORIGIN="
                + dummy_domains[1]
                + "\n"
            ),
        },
    )

    assert sorted(finding["File"] for finding in findings) == [
        "apps/dummy-network-outside-fixtures.py",
        "apps/dummy-network-outside-fixtures.py",
        "apps/dummy-outside-fixtures.py",
        "apps/dummy-outside-fixtures.py",
        "docs/dummy-outside-fixtures.md",
        "docs/dummy-outside-fixtures.md",
        "tests/fixtures-synthetic/non-dummy-network.py",
        "tests/fixtures-synthetic/non-dummy-network.py",
        "tests/fixtures-synthetic/non-dummy.md",
        "tests/fixtures-synthetic/non-dummy.md",
        "tests/fixtures-synthetic/non-dummy.py",
        "tests/fixtures-synthetic/non-dummy.py",
    ]
    assert {finding["RuleID"] for finding in findings} == expected_rules
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(domain not in report for domain in domains)
    assert all(dummy_domain not in report for dummy_domain in dummy_domains)


def test_actual_gitleaks_apex_domain_allowlist_requires_dummy_prefix_and_fixture_path(
    tmp_path: Path,
) -> None:
    """Arbitrary-TLD prose fixtures require both the path and DUMMY_ marker."""
    domain = "customer." + "finance"
    dummy_domain = "DUMMY_" + domain

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "tests/fixtures-synthetic/safe.toml": "note='" + dummy_domain + "'\n",
            "tests/fixtures-synthetic/non-dummy.toml": "note='" + domain + "'\n",
            "docs/dummy-outside-fixtures.md": "Use " + dummy_domain + " here.\n",
        },
    )
    apex_findings = [
        finding for finding in findings if finding["RuleID"] == "bare-apex-domain"
    ]

    assert sorted(finding["File"] for finding in apex_findings) == [
        "docs/dummy-outside-fixtures.md",
        "tests/fixtures-synthetic/non-dummy.toml",
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in apex_findings)


def test_actual_gitleaks_apex_domain_assignment_allowlist_requires_dummy_and_path(
    tmp_path: Path,
) -> None:
    """Arbitrary-TLD DOMAIN fixtures require both the path and DUMMY_ marker."""
    domain = "customer." + "finance"
    dummy_domain = "DUMMY_" + domain

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "tests/fixtures-synthetic/safe.py": "DOMAIN=" + dummy_domain + "\n",
            "tests/fixtures-synthetic/non-dummy.py": "DOMAIN=" + domain + "\n",
            "apps/dummy-outside-fixtures.py": "DOMAIN=" + dummy_domain + "\n",
        },
    )
    assignment_findings = [
        finding
        for finding in findings
        if finding["RuleID"] == "assigned-domain-name"
    ]

    assert sorted(finding["File"] for finding in assignment_findings) == [
        "apps/dummy-outside-fixtures.py",
        "tests/fixtures-synthetic/non-dummy.py",
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in assignment_findings)


def test_actual_gitleaks_bare_apex_rule_allows_reserved_and_public_hosts(
    tmp_path: Path,
) -> None:
    """Public documentation hosts must remain usable in prose and config."""
    assert actual_gitleaks_findings(
        tmp_path,
        {
            "docs/hosts.md": (
                "Examples: example.com, example.net, example.org, github.com, "
                "opensource.org, starlette.io, ghcr.io.\n"
            ),
            "deploy/docker/public.toml": "registry = \"pypi.org\"\n",
            "apps/api/Dockerfile": "FROM ghcr.io/astral-sh/uv:0.12.1\n",
            "apps/api/prose.py": "FORMAT = 'customer." + "com is documentation'\n",
            "apps/api/source.py": "domain = \"kb.customer.\" + \"com\"\n",
        },
    ) == []


def test_actual_gitleaks_requires_dummy_prefix_and_fixture_path(
    tmp_path: Path,
) -> None:
    """The host-assignment exception requires both fixture path and DUMMY_."""
    domain = "kb.customer." + "com"
    dummy_domain = "DUMMY_" + domain

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "tests/fixtures-synthetic/safe.txt": "KB_HOST=" + dummy_domain + "\n",
            "tests/fixtures-synthetic/non-dummy.txt": "KB_HOST=" + domain + "\n",
            "outside-fixtures.txt": "KB_HOST=" + dummy_domain + "\n",
        },
    )
    assignment_findings = [
        finding
        for finding in findings
        if finding["RuleID"] == "assigned-network-domain"
    ]

    assert sorted(finding["File"] for finding in assignment_findings) == [
        "outside-fixtures.txt",
        "tests/fixtures-synthetic/non-dummy.txt",
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in assignment_findings)


def test_actual_gitleaks_apex_allowlist_requires_dummy_prefix_and_fixture_path(
    tmp_path: Path,
) -> None:
    """The apex-domain exception retains DUMMY_ path-and-value AND semantics."""
    domain = "customer." + "com"
    dummy_domain = "DUMMY_" + domain

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "tests/fixtures-synthetic/safe.toml": "note = '" + dummy_domain + "'\n",
            "tests/fixtures-synthetic/non-dummy.toml": "note = '" + domain + "'\n",
            "docs/dummy-outside-fixtures.md": "Use " + dummy_domain + " here.\n",
        },
    )

    assert sorted(finding["File"] for finding in findings) == [
        "docs/dummy-outside-fixtures.md",
        "tests/fixtures-synthetic/non-dummy.toml",
    ]
    assert all(finding["RuleID"] == "bare-apex-domain" for finding in findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)


def test_actual_gitleaks_path_policy_requires_dummy_prefix_and_fixture_path(
    tmp_path: Path,
) -> None:
    """The isolated path policy must preserve its path-and-value AND exception."""
    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "tests/fixtures-synthetic/safe.txt": (
                "HOME=DUMMY_/" + "Users/example/project\n"
            ),
            "tests/fixtures-synthetic/non-dummy.txt": (
                "HOME=/" + "Users/example/project\n"
            ),
            "outside-fixtures.txt": "HOME=DUMMY_/" + "Users/example/project\n",
        },
        config_name=".gitleaks-paths.toml",
    )

    assert sorted(finding["File"] for finding in findings) == [
        "outside-fixtures.txt",
        "tests/fixtures-synthetic/non-dummy.txt",
    ]
    assert all(finding["RuleID"] == "macos-user-home-path" for finding in findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)


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
