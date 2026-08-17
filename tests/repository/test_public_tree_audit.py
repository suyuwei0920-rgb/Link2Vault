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

from scripts.audit_public_tree import Finding, audit_tree

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


def run_public_tree_audit(
    root: Path, *, history: bool = False
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(REPOSITORY_ROOT / "scripts/audit_public_tree.py"),
        str(root),
    ]
    if history:
        command.extend(["--history", "HEAD"])
    return subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )


def prepare_audit_visibility(
    root: Path, files: dict[str, str | bytes], visibility: str
) -> None:
    write_allowlist(root)
    write_file(root, "README.md", "# public\n")
    if visibility == "current":
        for relative, content in files.items():
            write_file(root, relative, content)
        return

    initialize_git_repository(root)
    if visibility == "history":
        configure_test_git_identity(root)
        commit_all(root, "initial public tree")

    for relative, content in files.items():
        write_file(root, relative, content)

    if visibility == "index":
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    elif visibility == "history":
        commit_all(root, "add unsafe audit blobs")
    else:
        raise AssertionError(f"unknown audit visibility: {visibility}")

    for relative in files:
        (root / relative).unlink()

    if visibility == "history":
        commit_all(root, "delete unsafe audit blobs")


@pytest.mark.parametrize("visibility", ["current", "index", "history"])
def test_malformed_endpoint_blobs_fail_closed_without_clear_output(
    tmp_path: Path, visibility: str
) -> None:
    """Parser failures in any audited blob must become generic findings."""
    malformed_endpoints = {
        "apps/bad-bracket.py": (
            "URL=" + "http" + "://" + "[" + "not-an-ip]\n"
        ),
        "apps/secret-bracket.py": (
            "WEBHOOK_URL=" + "https" + "://[" + "secret-shaped-value]/hook\n"
        ),
        "apps/bad-zone.py": (
            "DATABASE_URL="
            + "postgresql"
            + "://"
            + "user:pass@[bad-zone%25name]:99999/db\n"
        ),
        "apps/bad-port.py": (
            "SOURCE_URL="
            + "https"
            + "://"
            + "example.invalid:99999/status\n"
        ),
    }
    prepare_audit_visibility(tmp_path, malformed_endpoints, visibility)

    completed = run_public_tree_audit(
        tmp_path, history=visibility == "history"
    )

    assert completed.returncode == 1
    assert completed.stderr == ""
    assert completed.stdout.count(": malformed_endpoint: REDACTED") == len(
        malformed_endpoints
    )
    for stream in (completed.stdout, completed.stderr):
        assert all(
            clear_text not in stream
            for clear_text in (
                "not-an-ip",
                "secret-shaped-value",
                "user",
                "pass",
                "user:pass",
                "bad-zone%25name",
                "99999",
            )
        )
        assert all(
            exception_text not in stream
            for exception_text in (
                "Traceback",
                "ValueError",
                "does not appear to be",
                "Port out of range",
            )
        )


@pytest.mark.parametrize(
    ("unsafe_path", "username", "suffix"),
    [
        (
            "/" + "Users/alice/private/project/secret.txt",
            "alice",
            "private/project/secret.txt",
        ),
        (
            "/" + "USERS/Bob/Client Data/key.txt",
            "Bob",
            "Client Data/key.txt",
        ),
        (
            "C:" + r"\Users\carol\private\token.txt",
            "carol",
            r"private\token.txt",
        ),
        (
            "c:/" + "USERS/dave/private/token.txt",
            "dave",
            "private/token.txt",
        ),
    ],
)
def test_finding_path_redaction_replaces_the_complete_home_path(
    unsafe_path: str, username: str, suffix: str
) -> None:
    """Partial home-root replacement would retain identity and path details."""
    finding = Finding(unsafe_path, "private_path", "REDACTED")

    assert finding.path == "<redacted-home-path>"
    assert username not in finding.path
    assert suffix not in finding.path


@pytest.mark.parametrize(
    ("visibility", "home_path", "username", "suffix"),
    [
        pytest.param(
            "current",
            "/" + "Users/alice/private/project/secret.txt",
            "alice",
            "private/project/secret.txt",
            id="current-macos-home",
        ),
        pytest.param(
            "current",
            "/" + "USERS/Bob/Client Data/key.txt",
            "Bob",
            "Client Data/key.txt",
            id="current-casefolded-macos-home",
        ),
        pytest.param(
            "index",
            "C:" + r"\Users\carol\private\token.txt",
            "carol",
            r"private\token.txt",
            id="index-windows-backslash-home",
        ),
        pytest.param(
            "history",
            "c:/" + "USERS/dave/private/token.txt",
            "dave",
            "private/token.txt",
            id="history-windows-forward-slash-home",
        ),
    ],
)
def test_finding_path_redaction_is_consistent_across_audit_outputs(
    tmp_path: Path,
    visibility: str,
    home_path: str,
    username: str,
    suffix: str,
) -> None:
    """Current, index, and history paths must share one safe renderer."""
    path_secret = "sk-" + "pathsecretvalue1234"
    hostile_filename = (
        "hostile-" + path_secret + "\t\x1b[31m\n: forged: value.pem"
    )
    relative_home_path = (
        "apps" + home_path
        if home_path.startswith("/")
        else "apps/" + home_path
    )
    files = {
        relative_home_path + "/" + hostile_filename: "generic material\n",
        "apps/nonhome-" + hostile_filename: "generic material\n",
    }
    prepare_audit_visibility(tmp_path, files, visibility)

    completed = run_public_tree_audit(
        tmp_path, history=visibility == "history"
    )

    assert completed.returncode == 1
    assert completed.stderr == ""
    assert len(completed.stdout.splitlines()) == 2
    assert (
        "<redacted-home-path>: signing_material: <signing_material>"
        in completed.stdout
    )
    assert "<redacted-secret>" in completed.stdout
    assert r"\t" in completed.stdout
    assert r"\n" in completed.stdout
    assert r"\x1b" in completed.stdout
    assert "\t" not in completed.stdout
    assert "\x1b" not in completed.stdout
    assert ": forged: " not in completed.stdout
    for stream in (completed.stdout, completed.stderr):
        assert path_secret not in stream
        assert home_path not in stream
        assert username not in stream
        assert suffix not in stream


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
    media = write_file(
        tmp_path,
        "tests/fixtures-synthetic/sample.m4a",
        b"\x00\xff\x80\xfeSYNTHETIC\x00\x01",
    )
    digest = hashlib.sha256(media.read_bytes()).hexdigest()
    write_file(
        tmp_path,
        "tests/fixtures-synthetic/MANIFEST.sha256",
        f"{digest}  sample.m4a generated=true\n",
    )

    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "-f", "."], cwd=tmp_path, check=True)

    assert audit_tree(tmp_path) == []


def test_audit_tree_never_allows_manifested_archives_as_synthetic_fixtures(
    tmp_path: Path,
) -> None:
    """A self-attested archive could conceal private files and must stay intrinsic."""
    write_allowlist(tmp_path)
    archive = write_file(
        tmp_path,
        "tests/fixtures-synthetic/private.zip",
        b"PK\x03\x04\xff.env\x00sk-" + b"private-fixture-value",
    )
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    write_file(
        tmp_path,
        "tests/fixtures-synthetic/MANIFEST.sha256",
        f"{digest}  private.zip generated=true\n",
    )
    assert findings_by_path(tmp_path)["tests/fixtures-synthetic/private.zip"] == {
        "binary_artifact"
    }
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "-f", "."], cwd=tmp_path, check=True)

    assert findings_by_path(tmp_path)["tests/fixtures-synthetic/private.zip"] == {
        "binary_artifact"
    }


def test_audit_tree_bounds_manifested_media_consistently_in_index_and_worktree(
    tmp_path: Path,
) -> None:
    """Manifest self-attestation must not bypass the public content-size bound."""
    write_allowlist(tmp_path)
    media = write_file(
        tmp_path,
        "tests/fixtures-synthetic/oversized.m4a",
        b"x" * (2 * 1024 * 1024 + 1),
    )
    digest = hashlib.sha256(media.read_bytes()).hexdigest()
    write_file(
        tmp_path,
        "tests/fixtures-synthetic/MANIFEST.sha256",
        f"{digest}  oversized.m4a generated=true\n",
    )
    assert findings_by_path(tmp_path)["tests/fixtures-synthetic/oversized.m4a"] == {
        "media_file"
    }
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "-f", "."], cwd=tmp_path, check=True)

    assert findings_by_path(tmp_path)["tests/fixtures-synthetic/oversized.m4a"] == {
        "media_file"
    }


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


def configure_test_git_identity(root: Path) -> None:
    subprocess.run(
        ["git", "config", "user.name", "Link2Vault Tests"], cwd=root, check=True
    )
    subprocess.run(
        ["git", "config", "user.email", "tests@example.invalid"],
        cwd=root,
        check=True,
    )


def commit_all(root: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", message], cwd=root, check=True
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


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


def test_history_mode_audits_deleted_paths_blobs_modes_and_symlink_metadata(
    tmp_path: Path,
) -> None:
    """A clean tip must not hide an unsafe object retained in reachable history."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "README.md", "# clean public tip\n")
    initialize_git_repository(tmp_path)
    configure_test_git_identity(tmp_path)
    commit_all(tmp_path, "initial public tree")

    clear_secret = "sk-" + "historical-private-value"
    write_file(tmp_path, "donor-private.txt", "generic donor material\n")
    write_file(tmp_path, "apps/unsafe.py", "TOKEN = '" + clear_secret + "'\n")
    write_file(tmp_path, "apps/worker.LOG", "runtime transcript data\n")
    write_file(
        tmp_path,
        "apps/oversized.txt",
        "x" * (2 * 1024 * 1024 + 1),
    )
    (tmp_path / "apps" / "home-link.txt").symlink_to(
        "/" + "Users/alice/private"
    )
    unsafe_commit = commit_all(tmp_path, "add unsafe historical objects")

    for relative in (
        "donor-private.txt",
        "apps/unsafe.py",
        "apps/worker.LOG",
        "apps/oversized.txt",
        "apps/home-link.txt",
    ):
        (tmp_path / relative).unlink()
    commit_all(tmp_path, "delete unsafe historical objects")

    assert audit_tree(tmp_path) == []

    completed = subprocess.run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "scripts/audit_public_tree.py"),
            str(tmp_path),
            "--history",
            "HEAD",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert {
        "not_allowlisted",
        "credential",
        "runtime_artifact",
        "TEXT_TOO_LARGE",
        "symlink_user_home_target",
    } <= {
        line.split(": ", 2)[1] for line in completed.stdout.splitlines()
    }
    assert all(
        unsafe_commit + ":" + relative in completed.stdout
        for relative in (
            "donor-private.txt",
            "apps/unsafe.py",
            "apps/worker.LOG",
            "apps/oversized.txt",
            "apps/home-link.txt",
        )
    )
    assert clear_secret not in completed.stdout
    assert subprocess.run(
        ["git", "status", "--short"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""


def test_history_mode_fails_closed_when_repository_history_is_shallow(
    tmp_path: Path,
) -> None:
    """A depth-one clone cannot certify deleted objects from missing ancestry."""
    source = tmp_path / "source"
    clone = tmp_path / "clone"
    source.mkdir()
    write_allowlist(source)
    write_file(source, "README.md", "# public\n")
    initialize_git_repository(source)
    configure_test_git_identity(source)
    commit_all(source, "initial public tree")
    write_file(source, "apps/unsafe.py", "TOKEN = 'sk-" + "historical-value'\n")
    commit_all(source, "add historical secret")
    (source / "apps/unsafe.py").unlink()
    commit_all(source, "delete historical secret")
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", source.as_uri(), str(clone)],
        check=True,
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "scripts/audit_public_tree.py"),
            str(clone),
            "--history",
            "HEAD",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "SHALLOW_HISTORY" in completed.stdout
    assert "historical-value" not in completed.stdout


def test_history_mode_redacts_secret_and_control_characters_in_deleted_paths(
    tmp_path: Path,
) -> None:
    """Unsafe historical filenames must not forge or disclose CI output lines."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "README.md", "# public\n")
    initialize_git_repository(tmp_path)
    configure_test_git_identity(tmp_path)
    commit_all(tmp_path, "initial public tree")

    path_secret = "sk-" + "pathsecretvalue1234"
    unsafe_path = "donor-" + path_secret + "\t\x1b[31m\n: forged: value.txt"
    write_file(tmp_path, unsafe_path, "generic donor material\n")
    unsafe_commit = commit_all(tmp_path, "add hostile historical path")
    (tmp_path / unsafe_path).unlink()
    commit_all(tmp_path, "delete hostile historical path")

    completed = subprocess.run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "scripts/audit_public_tree.py"),
            str(tmp_path),
            "--history",
            "HEAD",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert unsafe_commit in completed.stdout
    assert path_secret not in completed.stdout
    assert "\x1b" not in completed.stdout
    assert "\t" not in completed.stdout
    assert "<redacted-secret>" in completed.stdout
    assert "\\t" in completed.stdout
    assert "\\n" in completed.stdout
    assert "\\x1b" in completed.stdout
    assert ": forged: " not in completed.stdout


def test_history_mode_rejects_deleted_gitlink_modes(tmp_path: Path) -> None:
    """A deleted 160000 entry must remain visible to the object-only history gate."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "README.md", "# public\n")
    initialize_git_repository(tmp_path)
    configure_test_git_identity(tmp_path)
    initial_commit = commit_all(tmp_path, "initial public tree")

    subprocess.run(
        [
            "git",
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{initial_commit},apps/vendor",
        ],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "add historical gitlink"],
        cwd=tmp_path,
        check=True,
    )
    gitlink_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "rm", "-q", "--cached", "apps/vendor"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "commit", "-q", "-m", "delete historical gitlink"],
        cwd=tmp_path,
        check=True,
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(REPOSITORY_ROOT / "scripts/audit_public_tree.py"),
            str(tmp_path),
            "--history",
            "HEAD",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert f"{gitlink_commit}:apps/vendor: gitlink: <gitlink>" in completed.stdout


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


INTRINSIC_PRIVATE_ARTIFACTS = (
    pytest.param("apps/SERVICE.LOG", "runtime_artifact", id="log"),
    pytest.param("apps/CAPTIONS.SRT", "runtime_artifact", id="srt"),
    pytest.param("apps/VIDEO.VTT", "runtime_artifact", id="vtt"),
    pytest.param(
        "apps/CALL.TRANSCRIPT.JSON", "runtime_artifact", id="transcript-export"
    ),
    pytest.param("apps/state.sqlite3-WAL", "database_sidecar", id="sqlite-wal"),
    pytest.param("apps/state.DB-ShM", "database_sidecar", id="sqlite-shm"),
    pytest.param(
        "apps/state.sqlite-JOURNAL", "database_sidecar", id="sqlite-journal"
    ),
    pytest.param("apps/__PyCaChE__/module.py", "generated_path", id="pycache"),
    pytest.param("apps/.PyTest_Cache/state", "generated_path", id="pytest-cache"),
    pytest.param("apps/.RuFf_CaChE/state", "generated_path", id="ruff-cache"),
    pytest.param("apps/.VeNv/bin/tool", "generated_path", id="venv"),
    pytest.param("apps/Node_Modules/pkg.js", "generated_path", id="node-modules"),
    pytest.param("apps/DIST/bundle.js", "generated_path", id="dist"),
    pytest.param("apps/Build/result.txt", "generated_path", id="build"),
    pytest.param("apps/.NEXT/result.txt", "generated_path", id="next"),
    pytest.param("apps/.Nuxt/result.txt", "generated_path", id="nuxt"),
    pytest.param("apps/.Svelte-Kit/result.txt", "generated_path", id="svelte-kit"),
    pytest.param("apps/Coverage/result.txt", "generated_path", id="coverage"),
    pytest.param("apps/.IDEA/workspace.xml", "ide_state", id="idea"),
    pytest.param("apps/.VsCode/settings.json", "ide_state", id="vscode"),
    pytest.param("apps/project.IML", "ide_state", id="iml"),
    pytest.param("apps/.Ds_Store", "ide_state", id="ds-store"),
    pytest.param("apps/Thumbs.DB", "ide_state", id="thumbs-db"),
    pytest.param("apps/module.PYC", "generated_file", id="pyc"),
    pytest.param("apps/module$PY.CLASS", "generated_file", id="dollar-py-class"),
    pytest.param("apps/production.ENV", "environment_file", id="named-env"),
    pytest.param("apps/signing.P8", "signing_material", id="apple-private-key"),
    pytest.param("apps/signing.PPK", "signing_material", id="putty-private-key"),
    pytest.param("apps/certificate.CER", "signing_material", id="certificate-cer"),
    pytest.param("apps/certificate.DER", "signing_material", id="certificate-der"),
    pytest.param(
        "apps/profile.MOBILEPROVISION",
        "signing_material",
        id="mobile-provisioning-profile",
    ),
)


@pytest.mark.parametrize(("relative", "expected_rule"), INTRINSIC_PRIVATE_ARTIFACTS)
def test_audit_tree_intrinsically_rejects_private_artifacts_from_staged_blobs(
    tmp_path: Path, relative: str, expected_rule: str
) -> None:
    """Deleting an ignored artifact after force-add must not mask its staged blob."""
    write_allowlist(tmp_path)
    write_file(tmp_path, ".gitignore", "apps/\n")
    artifact = write_file(tmp_path, relative, "synthetic private state\n")
    initialize_git_repository(tmp_path)
    subprocess.run(
        ["git", "add", ".public-allowlist", ".gitignore"], cwd=tmp_path, check=True
    )
    subprocess.run(["git", "add", "-f", relative], cwd=tmp_path, check=True)
    artifact.unlink()

    assert findings_by_path(tmp_path)[relative] == {expected_rule}


@pytest.mark.parametrize(("relative", "expected_rule"), INTRINSIC_PRIVATE_ARTIFACTS)
def test_audit_tree_intrinsically_rejects_private_artifacts_from_worktree(
    tmp_path: Path, relative: str, expected_rule: str
) -> None:
    """An untracked worktree candidate must be denied without an index finding."""
    write_allowlist(tmp_path)
    write_file(tmp_path, relative, "synthetic private state\n")
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", ".public-allowlist"], cwd=tmp_path, check=True)

    assert findings_by_path(tmp_path)[relative] == {expected_rule}


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


def test_audit_tree_accepts_a_staged_symlink_to_an_allowlisted_directory(
    tmp_path: Path,
) -> None:
    """Index metadata must recognize directories represented only by tree prefixes."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "apps/public-dir/target.txt", "safe\n")
    (tmp_path / "apps" / "public-link").symlink_to("public-dir")
    initialize_git_repository(tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)

    assert audit_tree(tmp_path) == []


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
            "IPV6_ZONE = 'https://" + "[fe80::1%25en0]/v1'\n",
            {"deployment_endpoint"},
        ),
        (
            "ROOT_DOT = 'https://" + "api.customer.finance./v1'\n",
            {"deployment_endpoint"},
        ),
        (
            "DSN_ROOT_DOT = 'postgresql://" + "db.customer.finance./app'\n",
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


@pytest.mark.parametrize(
    "scheme",
    [
        "postgresql",
        "postgresql+asyncpg",
        "postgresql+psycopg",
        "postgres",
        "mysql",
        "mysql+aiomysql",
        "mysql+pymysql",
        "mariadb",
        "mariadb+mariadbconnector",
        "redis",
        "redis+sentinel",
        "rediss",
        "mongodb",
        "mongodb+srv",
        "amqp",
        "amqps",
        "kafka",
        "nats",
    ],
)
def test_audit_tree_rejects_reviewed_production_dsn_schemes(
    tmp_path: Path, scheme: str
) -> None:
    """Limiting endpoint inspection to HTTP(S) would expose production DSNs."""
    write_allowlist(tmp_path)
    unsafe_host = "db.customer." + "finance"
    write_file(
        tmp_path,
        "apps/dsn.py",
        "CONNECTION = '" + scheme + "://" + unsafe_host + "/application'\n",
    )

    findings = audit_tree(tmp_path)

    assert {finding.rule for finding in findings} == {"deployment_endpoint"}
    assert unsafe_host not in repr(findings)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        pytest.param(
            "DATABASE_URL",
            "postgresql" + "://db.customer.finance/application",
            id="database-url-dsn",
        ),
        pytest.param(
            "CACHE_URI",
            "rediss" + "://cache.customer.technology/0",
            id="composite-uri-dsn",
        ),
        pytest.param(
            "EVENT_DSN",
            "mongodb+srv" + "://cluster.customer.xn--fiqs8s/app",
            id="composite-dsn-punycode",
        ),
        pytest.param(
            "WEBHOOK",
            "hooks.customer." + "solutions",
            id="exact-webhook-host",
        ),
        pytest.param(
            "ORDER_WEBHOOK_URL",
            "hooks.customer." + "technology",
            id="composite-webhook-url-host",
        ),
        pytest.param(
            "WEBHOOK",
            "[fd00::8]",
            id="bare-private-ipv6-webhook",
        ),
        pytest.param(
            "SERVICE_URI",
            "[fe80::1%25en0]:8080",
            id="bare-link-local-zone-ipv6-uri",
        ),
        pytest.param(
            "DATABASE_URL",
            "[fd12:3456::9]:5432",
            id="bare-private-ipv6-url",
        ),
    ],
)
def test_audit_tree_rejects_explicit_endpoint_assignment_keys(
    tmp_path: Path, key: str, value: str
) -> None:
    """Explicit URL, URI, DSN, and webhook keys must own arbitrary endpoint hosts."""
    write_allowlist(tmp_path)
    write_file(tmp_path, "apps/endpoints.py", key + " = '" + value + "'\n")

    findings = audit_tree(tmp_path)

    assert "deployment_endpoint" in {finding.rule for finding in findings}
    assert value not in repr(findings)


def test_audit_tree_redacts_dsn_userinfo_and_sensitive_query_values(
    tmp_path: Path,
) -> None:
    """Endpoint findings must never echo DSN userinfo or query credentials."""
    write_allowlist(tmp_path)
    unsafe_host = "db.customer." + "finance"
    username = "private-user"
    password = "private-password"
    token = "private-query-token"
    dsn = (
        "postgresql+asyncpg://"
        + username
        + ":"
        + password
        + "@"
        + unsafe_host
        + "/app?token="
        + token
    )
    write_file(tmp_path, "apps/credentials.py", "DATABASE_URL = '" + dsn + "'\n")

    findings = audit_tree(tmp_path)

    assert {finding.rule for finding in findings} == {
        "credential",
        "deployment_endpoint",
    }
    assert all(
        clear_value not in repr(findings)
        for clear_value in (username, password, token, unsafe_host, dsn)
    )


@pytest.mark.parametrize(
    "private_host",
    [
        "10.0." + "0.8",
        "169.254." + "169.254",
        "[fd00::8]",
        "service.internal",
    ],
)
def test_audit_tree_rejects_ssrf_private_dsn_hosts(
    tmp_path: Path, private_host: str
) -> None:
    """Private and link-local DSN targets are never canonical public examples."""
    write_allowlist(tmp_path)
    write_file(
        tmp_path,
        "apps/private_dsn.py",
        "DATABASE_URL = 'redis://" + private_host + "/0'\n",
    )

    assert "deployment_endpoint" in {
        finding.rule for finding in audit_tree(tmp_path)
    }


def test_audit_tree_allows_only_safe_reserved_or_canonical_endpoint_assignments(
    tmp_path: Path,
) -> None:
    """Canonical and reserved hosts remain useful only without embedded credentials."""
    write_allowlist(tmp_path)
    write_file(
        tmp_path,
        "apps/safe_endpoints.py",
        "DATABASE_URL = 'postgresql://localhost:5432/application'\n"
        "DRIVER_URL = 'postgresql+asyncpg://localhost:5432/application'\n"
        "CACHE_URI = 'redis://cache.example.test/0'\n"
        "WEBHOOK_URL = 'hooks.example.invalid'\n"
        "WEBHOOK = '[::1]'\n"
        "SERVICE_URI = '[::1]:8080'\n"
        "SOURCE_URL = 'https://docs.python.org/3/'\n",
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
    assert "uv run python scripts/audit_public_tree.py . --history HEAD" in (
        commands_by_job["public-tree-audit"]
    )
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
    assert jobs["docker-contract"]["runs-on"] == "${{ matrix.os }}"
    assert jobs["docker-contract"]["strategy"] == {
        "fail-fast": False,
        "matrix": {"os": ["ubuntu-22.04", "ubuntu-24.04"]},
    }

    gitleaks_checkout = next(
        step
        for step in jobs["gitleaks"]["steps"]
        if step.get("uses") == "actions/checkout@v7"
    )
    assert gitleaks_checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    history_checkout = next(
        step
        for step in jobs["public-tree-audit"]["steps"]
        if step.get("uses") == "actions/checkout@v7"
    )
    assert history_checkout["with"] == {
        "fetch-depth": 0,
        "persist-credentials": False,
    }
    assert jobs["dependency-review"]["if"] == "github.event_name == 'pull_request'"

    allowed_action_pins = {
        "actions/checkout@v7",
        "actions/setup-python@v6",
        "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9",
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
        if step.get("uses")
        == "astral-sh/setup-uv@c771a70e6277c0a99b617c7a806ffedaca235ff9"
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

    findings = actual_gitleaks_findings(tmp_path, {"apps/pressure.py": content})
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
        + "host)\napi.client.get\napi.logger.info\nGHOST=customer."
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


def test_actual_gitleaks_blocks_reviewed_dsn_schemes_and_redacts_full_values(
    tmp_path: Path,
) -> None:
    """HTTP-only matching would leak common database, cache, and broker DSNs."""
    unsafe_host = "db.customer." + "finance"
    schemes = (
        "postgresql",
        "postgresql+asyncpg",
        "postgresql+psycopg",
        "postgres",
        "mysql",
        "mysql+aiomysql",
        "mysql+pymysql",
        "mariadb",
        "mariadb+mariadbconnector",
        "redis",
        "redis+sentinel",
        "rediss",
        "mongodb",
        "mongodb+srv",
        "amqp",
        "amqps",
        "kafka",
        "nats",
    )
    endpoints = {
        scheme: scheme + "://" + unsafe_host + "/application"
        for scheme in schemes
    }

    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "apps/dsn-" + scheme.replace("+", "-") + ".py": (
                "CONNECTION = '" + endpoint + "'\n"
            )
            for scheme, endpoint in endpoints.items()
        },
    )

    dsn_findings = [
        finding
        for finding in findings
        if finding["RuleID"] == "production-dsn-endpoint"
    ]
    assert len(dsn_findings) == len(schemes)
    assert all(finding["Secret"] == "REDACTED" for finding in dsn_findings)
    report = json.dumps(findings)
    assert all(endpoint not in report for endpoint in endpoints.values())
    assert unsafe_host not in report


def test_actual_gitleaks_blocks_explicit_url_uri_dsn_and_webhook_assignments(
    tmp_path: Path,
) -> None:
    """Explicit endpoint keys must detect both scheme URLs and bare Punycode hosts."""
    values = {
        "DATABASE_URL": "postgresql" + "://db.customer.finance/application",
        "CACHE_URI": "rediss" + "://cache.customer.technology/0",
        "EVENT_DSN": "mongodb+srv" + "://cluster.customer.xn--fiqs8s/app",
        "WEBHOOK": "hooks." + "customer.solutions",
        "ORDER_WEBHOOK_URL": "hooks." + "customer.technology",
        "PRIVATE_WEBHOOK": "[fd00" + "::8]",
        "SERVICE_URI": "[fe80" + "::1%25en0]:8080",
        "REPLICA_URL": "[fd12" + ":3456::9]:5432",
    }
    content = "\n".join(key + "='" + value + "'" for key, value in values.items())

    findings = actual_gitleaks_findings(
        tmp_path,
        {"apps/explicit-endpoints.py": content + "\n"},
    )
    assigned_findings = [
        finding
        for finding in findings
        if finding["RuleID"] == "assigned-production-endpoint"
    ]

    line_counts = {
        line: sum(finding["StartLine"] == line for finding in assigned_findings)
        for line in range(1, len(values) + 1)
    }
    assert line_counts == {line: 1 for line in range(1, len(values) + 1)}, [
        (finding["StartColumn"], finding["EndColumn"], finding["Match"])
        for finding in assigned_findings
        if finding["StartLine"] == 7
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in assigned_findings)
    report = json.dumps(findings)
    assert all(value not in report for value in values.values())


def test_actual_gitleaks_dsn_userinfo_query_and_private_hosts_are_fully_redacted(
    tmp_path: Path,
) -> None:
    """Userinfo, query credentials, and SSRF-private hosts must not survive reports."""
    username = "private-user"
    password = "private-password"
    token = "private-query-token"
    unsafe_host = "db.customer." + "finance"
    credentialed = (
        "postgresql://"
        + username
        + ":"
        + password
        + "@"
        + unsafe_host
        + "/app?token="
        + token
    )
    private_endpoints = {
        "apps/private-ip.py": "redis://" + "10.0." + "0.8/0",
        "apps/link-local.py": (
            "redis://" + "169.254." + "169.254/0"
        ),
        "apps/private-v6.py": "redis://" + "[fd00::8]/0",
    }
    files = {
        "apps/credentialed.py": "DATABASE_URL='" + credentialed + "'\n",
        **{
            path: "DATABASE_URL='" + endpoint + "'\n"
            for path, endpoint in private_endpoints.items()
        },
    }

    findings = actual_gitleaks_findings(tmp_path, files)

    assert len(
        [
            finding
            for finding in findings
            if finding["RuleID"] == "production-dsn-endpoint"
        ]
    ) == 4
    report = json.dumps(findings)
    assert all(
        clear_value not in report
        for clear_value in (
            username,
            password,
            token,
            unsafe_host,
            credentialed,
            *private_endpoints.values(),
        )
    )


def test_actual_gitleaks_endpoint_allowlists_require_safe_host_and_no_credentials(
    tmp_path: Path,
) -> None:
    """Reserved/canonical endpoint exceptions must not excuse embedded credentials."""
    safe_values = {
        "DATABASE_URL": "postgresql://localhost:5432/application",
        "DRIVER_URL": "postgresql+asyncpg://localhost:5432/application",
        "CACHE_URI": "redis://cache.example.test/0",
        "WEBHOOK_URL": "hooks.example.invalid",
        "SOURCE_URL": "https://docs.python.org/3/",
        "REGISTRY_URL": "https://ghcr.io/example/image",
        "FRAMEWORK_URI": "https://fastapi.tiangolo.com/tutorial/",
        "RAW_URL": "https://raw.githubusercontent.com/example/test/main/file",
        "LOCAL_WEBHOOK": "[" + "::1]",
        "LOCAL_SERVICE_URI": "[" + "::1]:8080",
    }
    safe_content = "\n".join(
        key + "='" + value + "'" for key, value in safe_values.items()
    )
    credentialed_safe_host = (
        "postgresql+asyncpg://"
        + "private-user"
        + ":"
        + "private-password"
        + "@localhost/application"
    )

    assert actual_gitleaks_findings(
        tmp_path / "safe", {"apps/safe.py": safe_content + "\n"}
    ) == []

    unsafe_findings = actual_gitleaks_findings(
        tmp_path / "credentialed",
        {
            "apps/unsafe.py": (
                "DATABASE_URL='" + credentialed_safe_host + "'\n"
            )
        },
    )
    assert "production-dsn-endpoint" in {
        finding["RuleID"] for finding in unsafe_findings
    }
    assert credentialed_safe_host not in json.dumps(unsafe_findings)


def test_actual_gitleaks_endpoint_dummy_allowlists_require_path_and_prefix(
    tmp_path: Path,
) -> None:
    """New endpoint rules retain fixture-path plus DUMMY_ AND semantics."""
    endpoint = "postgresql" + "://db.customer.finance/application"
    dummy_endpoint = "DUMMY_" + endpoint
    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "tests/fixtures-synthetic/safe.py": (
                "DATABASE_URL='" + dummy_endpoint + "'\n"
            ),
            "tests/fixtures-synthetic/non-dummy.py": (
                "DATABASE_URL='" + endpoint + "'\n"
            ),
            "apps/dummy-outside.py": "DATABASE_URL='" + dummy_endpoint + "'\n",
            "tests/fixtures-synthetic/safe-ipv6.py": (
                "WEBHOOK='DUMMY_[fd00" + "::8]'\n"
            ),
            "tests/fixtures-synthetic/non-dummy-ipv6.py": (
                "WEBHOOK='[fd00" + "::8]'\n"
            ),
            "apps/dummy-ipv6-outside.py": (
                "WEBHOOK='DUMMY_[fd00" + "::8]'\n"
            ),
        },
    )

    findings_by_file: dict[str, set[str]] = {}
    for finding in findings:
        findings_by_file.setdefault(str(finding["File"]), set()).add(
            str(finding["RuleID"])
        )

    assert "tests/fixtures-synthetic/safe.py" not in findings_by_file
    assert "tests/fixtures-synthetic/safe-ipv6.py" not in findings_by_file
    assert {
        "production-dsn-endpoint",
        "assigned-production-endpoint",
    } <= findings_by_file["tests/fixtures-synthetic/non-dummy.py"]
    assert {
        "production-dsn-endpoint",
        "assigned-production-endpoint",
    } <= findings_by_file["apps/dummy-outside.py"]
    assert findings_by_file["tests/fixtures-synthetic/non-dummy-ipv6.py"] == {
        "assigned-production-endpoint"
    }
    assert findings_by_file["apps/dummy-ipv6-outside.py"] == {
        "assigned-production-endpoint"
    }


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
    owning_finding = next(
        finding for finding in findings if finding["RuleID"] == owning_rule
    )
    companion_finding = next(
        finding for finding in findings if finding["RuleID"] == companion_rule
    )
    # Human ruling: primaries retain domain-only captures, while companions
    # redact the complete validated pair so neither domain leaks via Match.
    assert owning_finding["Secret"] == "REDACTED"
    assert owning_finding["Match"] != "REDACTED"
    assert companion_finding["Secret"] == "REDACTED"
    assert companion_finding["Match"] == "REDACTED"
    assert len(
        {
            (
                finding["File"],
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


def domain_sequence_content(
    family: str, domains: list[str], separators: list[str]
) -> str:
    prefixes = {
        "bare": ["" for _domain in domains],
        "domain": [
            "DOMAIN=",
            "PUBLIC_DOMAIN=",
            "TENANT_DOMAIN=",
            "CUSTOMER_DOMAIN=",
            "SERVICE_DOMAIN=",
        ][: len(domains)],
        "network": ["HOST=", "ORIGIN=", "API_HOST=", "SERVER=", "ENDPOINT="][
            : len(domains)
        ],
    }[family]
    values = [prefix + domain for prefix, domain in zip(prefixes, domains, strict=True)]
    return "".join(
        value + (separators[index] if index < len(separators) else "")
        for index, value in enumerate(values)
    ) + "\n"


DOMAIN_SEQUENCE_FAMILIES = (
    pytest.param(
        "bare",
        "docs/domain-sequence.md",
        {"bare-apex-domain", "adjacent-bare-apex-domain"},
        id="bare-prose",
    ),
    pytest.param(
        "domain",
        "apps/domain-sequence.py",
        {"assigned-domain-name", "adjacent-assigned-domain-name"},
        id="domain-assignments",
    ),
    pytest.param(
        "network",
        "apps/network-sequence.py",
        {"assigned-network-domain", "adjacent-assigned-network-domain"},
        id="network-assignments",
    ),
)


@pytest.mark.parametrize(("family", "path", "owning_rules"), DOMAIN_SEQUENCE_FAMILIES)
@pytest.mark.parametrize("separator", [" ", "\t", ",", ";"])
def test_actual_gitleaks_domain_sequences_own_four_values_exactly_once(
    tmp_path: Path,
    family: str,
    path: str,
    owning_rules: set[str],
    separator: str,
) -> None:
    """A one-character delimiter must not create an unsafe fourth-value gap."""
    domains = [
        "alpha.customer." + "finance",
        "beta.customer." + "technology",
        "gamma.customer." + "solutions",
        "delta.customer." + "company",
    ]
    findings = actual_gitleaks_findings(
        tmp_path,
        {
            path: domain_sequence_content(
                family, domains, [separator] * (len(domains) - 1)
            )
        },
    )

    assert len(findings) == len(domains)
    assert {str(finding["RuleID"]) for finding in findings} == owning_rules
    spans = {
        (
            finding["File"],
            finding["StartLine"],
            finding["StartColumn"],
            finding["EndLine"],
            finding["EndColumn"],
        )
        for finding in findings
    }
    assert len(spans) == len(findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(domain not in report for domain in domains)


@pytest.mark.parametrize(
    ("domains", "separators"),
    [
        pytest.param(
            [
                "api.customer." + "finance",
                "worker.customer." + "technology",
                "hooks.customer." + "solutions",
                "service.customer." + "company",
            ],
            [";", ",", " "],
            id="arbitrary-tld-single-separators",
        ),
        pytest.param(
            [
                "api.customer." + "com",
                "worker.customer." + "net",
                "hooks.customer." + "org",
                "service.customer." + "io",
                "cdn.customer." + "dev",
            ],
            ["; ", ", ", "\t\t", " "],
            id="finite-tld-one-multi-separators",
        ),
    ],
)
def test_actual_gitleaks_deployment_prefix_sequences_have_one_finding_per_domain(
    tmp_path: Path, domains: list[str], separators: list[str]
) -> None:
    """Overlapping deployment and apex families must not duplicate domain spans."""
    findings = actual_gitleaks_findings(
        tmp_path,
        {"docs/deployment-sequence.md": domain_sequence_content("bare", domains, separators)},
    )

    assert len(findings) == len(domains)
    spans = {
        (
            finding["File"],
            finding["StartLine"],
            finding["StartColumn"],
            finding["EndLine"],
            finding["EndColumn"],
        )
        for finding in findings
    }
    assert len(spans) == len(findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(domain not in report for domain in domains)


@pytest.mark.parametrize(
    ("path", "owner"),
    [
        ("LICENSE", "bare-deployment-domain"),
        ("Makefile", "bare-deployment-domain"),
        ("apps/api/Dockerfile", "bare-apex-domain"),
        ("scripts/deploy.sh", "bare-deployment-domain"),
        ("docs/example.go", "bare-deployment-domain-docs-source"),
        ("config/settings.json", "bare-apex-domain"),
        ("Makefile.md", "bare-apex-domain"),
    ],
)
def test_actual_gitleaks_deployment_domain_path_ownership_is_exactly_once(
    tmp_path: Path, path: str, owner: str
) -> None:
    """Root, config, normal source, and docs-source paths each need one owner."""
    domain = "api.customer." + "com"
    findings = actual_gitleaks_findings(tmp_path, {path: domain + "\n"})

    assert len(findings) == 1
    assert findings[0]["RuleID"] == owner
    assert findings[0]["Secret"] == "REDACTED"
    assert domain not in json.dumps(findings)


@pytest.mark.parametrize(
    ("path", "owner"),
    [
        ("apps/source.py", "bare-deployment-domain"),
        ("docs/example.go", "bare-deployment-domain-docs-source"),
    ],
)
def test_actual_gitleaks_source_deployment_sequences_own_every_value_once(
    tmp_path: Path, path: str, owner: str
) -> None:
    """Source owners must not consume separators and skip even-numbered hosts."""
    domains = [
        "api.customer." + "com",
        "worker.customer." + "net",
        "hooks.customer." + "org",
        "service.customer." + "io",
        "cdn.customer." + "dev",
    ]
    content = domain_sequence_content("bare", domains, [";", ", ", "\t\t", " "])

    findings = actual_gitleaks_findings(tmp_path, {path: content})

    assert len(findings) == len(domains)
    assert {finding["RuleID"] for finding in findings} == {owner}
    assert len(
        {
            (
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
    assert all(domain not in report for domain in domains)


@pytest.mark.parametrize("path", ["apps/source.dart", "docs/example.scala"])
def test_actual_gitleaks_source_logging_member_allowance_is_language_neutral(
    tmp_path: Path, path: str
) -> None:
    """Every supported source owner needs the same exact logging-chain allowance."""
    assert actual_gitleaks_findings(tmp_path, {path: "api.logger.info\n"}) == []


@pytest.mark.parametrize(("family", "path", "owning_rules"), DOMAIN_SEQUENCE_FAMILIES)
@pytest.mark.parametrize(
    "separators",
    [
        [";", " ", ",", "\t"],
        ["  ", "; ", "\t\t", ", "],
        [", ", "\t", ";  ", " "],
    ],
    ids=["varied-single", "all-multi", "mixed-one-multi"],
)
def test_actual_gitleaks_domain_sequences_own_five_varied_values_without_duplicates(
    tmp_path: Path,
    family: str,
    path: str,
    owning_rules: set[str],
    separators: list[str],
) -> None:
    """Finite ordinal companions must not be required for longer mixed sequences."""
    domains = [
        "alpha.customer." + "finance",
        "beta.customer." + "technology",
        "gamma.customer." + "solutions",
        "delta.customer." + "company",
        "epsilon.customer." + "international",
    ]
    findings = actual_gitleaks_findings(
        tmp_path,
        {path: domain_sequence_content(family, domains, separators)},
    )

    assert len(findings) == len(domains)
    assert {str(finding["RuleID"]) for finding in findings} <= owning_rules
    spans = {
        (
            finding["File"],
            finding["StartLine"],
            finding["StartColumn"],
            finding["EndLine"],
            finding["EndColumn"],
        )
        for finding in findings
    }
    assert len(spans) == len(findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(domain not in report for domain in domains)


@pytest.mark.parametrize(("family", "path", "owning_rules"), DOMAIN_SEQUENCE_FAMILIES)
def test_actual_gitleaks_domain_sequences_block_unsafe_tail_after_three_safe_values(
    tmp_path: Path,
    family: str,
    path: str,
    owning_rules: set[str],
) -> None:
    """Three allowlisted prefixes must not suppress unsafe fourth and fifth values."""
    safe_domains = ["example.test", "docs.python.org", "api.github.com"]
    unsafe_tail = [
        "delta.customer." + "company",
        "epsilon.customer." + "international",
    ]
    findings = actual_gitleaks_findings(
        tmp_path,
        {
            path: domain_sequence_content(
                family, safe_domains + unsafe_tail, [";", " ", ",", "\t"]
            )
        },
    )

    assert len(findings) == len(unsafe_tail)
    assert {str(finding["RuleID"]) for finding in findings} <= owning_rules
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(domain not in report for domain in safe_domains + unsafe_tail)


@pytest.mark.parametrize(("family", "path", "owning_rules"), DOMAIN_SEQUENCE_FAMILIES)
def test_actual_gitleaks_domain_sequences_block_unsafe_fourth_after_safe_prefix(
    tmp_path: Path,
    family: str,
    path: str,
    owning_rules: set[str],
) -> None:
    """A safe three-value prefix must not hide the final unsafe fourth value."""
    safe_domains = ["example.test", "docs.python.org", "api.github.com"]
    unsafe_domain = "delta.customer." + "company"
    findings = actual_gitleaks_findings(
        tmp_path,
        {
            path: domain_sequence_content(
                family, safe_domains + [unsafe_domain], [";", " ", ","]
            )
        },
    )

    assert len(findings) == 1
    assert {str(finding["RuleID"]) for finding in findings} <= owning_rules
    assert findings[0]["Secret"] == "REDACTED"
    report = json.dumps(findings)
    assert all(domain not in report for domain in safe_domains + [unsafe_domain])


@pytest.mark.parametrize(("family", "path", "owning_rules"), DOMAIN_SEQUENCE_FAMILIES)
def test_actual_gitleaks_domain_sequences_preserve_dummy_path_and_value_semantics(
    tmp_path: Path,
    family: str,
    path: str,
    owning_rules: set[str],
) -> None:
    """Long-sequence ownership keeps fixture path AND DUMMY_ semantics."""
    del path
    domains = [
        "alpha.customer." + "finance",
        "beta.customer." + "technology",
        "gamma.customer." + "solutions",
        "delta.customer." + "company",
        "epsilon.customer." + "international",
    ]
    dummy_domains = ["DUMMY_" + domain for domain in domains]
    extension = ".md" if family == "bare" else ".py"
    files = {
        "tests/fixtures-synthetic/safe-sequence" + extension: (
            domain_sequence_content(family, dummy_domains, [";", " ", ",", "\t"])
        ),
        "tests/fixtures-synthetic/unsafe-tail-sequence" + extension: (
            domain_sequence_content(
                family,
                dummy_domains[:3] + domains[3:],
                [";", " ", ",", "\t"],
            )
        ),
        "docs/dummy-outside-sequence.md"
        if family == "bare"
        else "apps/dummy-outside-sequence.py": domain_sequence_content(
            family, dummy_domains, [";", " ", ",", "\t"]
        ),
    }
    findings = actual_gitleaks_findings(tmp_path, files)
    findings_by_file: dict[str, list[dict[str, object]]] = {}
    for finding in findings:
        findings_by_file.setdefault(str(finding["File"]), []).append(finding)

    assert "tests/fixtures-synthetic/safe-sequence" + extension not in findings_by_file
    unsafe_fixture_findings = findings_by_file[
        "tests/fixtures-synthetic/unsafe-tail-sequence" + extension
    ]
    assert len(unsafe_fixture_findings) == 2
    assert {str(finding["RuleID"]) for finding in unsafe_fixture_findings} <= (
        owning_rules
    )
    outside_path = (
        "docs/dummy-outside-sequence.md"
        if family == "bare"
        else "apps/dummy-outside-sequence.py"
    )
    assert len(findings_by_file[outside_path]) == len(dummy_domains)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(domain not in report for domain in domains + dummy_domains)


@pytest.mark.parametrize(
    ("path", "content", "unsafe_domains", "owning_rule", "companion_rule"),
    [
        pytest.param(
            "apps/domain-settings.py",
            "'DOMAIN'='alpha."
            + "review';'PUBLIC_DOMAIN'='beta."
            + "review'\n",
            ["alpha." + "review", "beta." + "review"],
            "assigned-domain-name",
            "adjacent-assigned-domain-name",
            id="single-quoted-domain-assignments",
        ),
        pytest.param(
            "apps/network-settings.py",
            "'HOST'='api.alpha."
            + "com';'ORIGIN'='api.beta."
            + "com'\n",
            ["api.alpha." + "com", "api.beta." + "com"],
            "assigned-network-domain",
            "adjacent-assigned-network-domain",
            id="single-quoted-network-assignments",
        ),
        pytest.param(
            "apps/ported-settings.py",
            '"DOMAIN"="alpha.'
            + 'review:8443";"PUBLIC_DOMAIN"="beta.'
            + 'review:9443"\n',
            ["alpha." + "review", "beta." + "review"],
            "assigned-domain-name",
            "adjacent-assigned-domain-name",
            id="double-quoted-ported-domain-assignments",
        ),
    ],
)
def test_actual_gitleaks_apex_domain_quoted_pairs_need_no_companion(
    tmp_path: Path,
    path: str,
    content: str,
    unsafe_domains: list[str],
    owning_rule: str,
    companion_rule: str,
) -> None:
    """A closing quote leaves the separator available to both primary matches."""
    findings = actual_gitleaks_findings(tmp_path, {path: content})

    assert len(findings) == 2
    assert {finding["RuleID"] for finding in findings} == {owning_rule}
    assert companion_rule not in {finding["RuleID"] for finding in findings}
    assert len(
        {
            (
                finding["File"],
                finding["StartLine"],
                finding["StartColumn"],
                finding["EndLine"],
                finding["EndColumn"],
            )
            for finding in findings
        }
    ) == len(findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    assert all(finding["Match"] != "REDACTED" for finding in findings)
    report = json.dumps(findings)
    assert all(unsafe_domain not in report for unsafe_domain in unsafe_domains)


@pytest.mark.parametrize(
    (
        "path",
        "invalid_first",
        "valid_first",
        "second",
        "owning_rule",
        "companion_rule",
    ),
    [
        pytest.param(
            "apps/domain-settings.py",
            "NOTE=release." + "finance",
            "DOMAIN=release." + "finance",
            "DOMAIN=customer." + "technology",
            "assigned-domain-name",
            "adjacent-assigned-domain-name",
            id="domain-assignments",
        ),
        pytest.param(
            "apps/network-settings.py",
            "NOTE=release." + "finance",
            "HOST=release." + "finance",
            "HOST=api.customer." + "com",
            "assigned-network-domain",
            "adjacent-assigned-network-domain",
            id="network-assignments",
        ),
        pytest.param(
            "docs/adjacent.md",
            "x_release." + "finance",
            "release." + "finance",
            "customer." + "technology",
            "bare-apex-domain",
            "adjacent-bare-apex-domain",
            id="bare-prose",
        ),
    ],
)
def test_actual_gitleaks_apex_domain_companion_requires_owned_first_value(
    tmp_path: Path,
    path: str,
    invalid_first: str,
    valid_first: str,
    second: str,
    owning_rule: str,
    companion_rule: str,
) -> None:
    """A TLD-like suffix is not enough to activate a companion rule."""
    invalid_findings = actual_gitleaks_findings(
        tmp_path / "invalid",
        {path: invalid_first + ";" + second + "\n"},
    )

    assert len(invalid_findings) == 1
    assert {finding["RuleID"] for finding in invalid_findings} == {owning_rule}
    assert companion_rule not in {
        finding["RuleID"] for finding in invalid_findings
    }
    assert len(
        {
            (
                finding["File"],
                finding["StartLine"],
                finding["StartColumn"],
                finding["EndLine"],
                finding["EndColumn"],
            )
            for finding in invalid_findings
        }
    ) == len(invalid_findings)
    assert all(finding["Secret"] == "REDACTED" for finding in invalid_findings)
    assert invalid_findings[0]["Match"] != "REDACTED"
    invalid_report = json.dumps(invalid_findings)
    assert invalid_first.split("=", 1)[-1].removeprefix("x_") not in invalid_report
    assert second.split("=", 1)[-1] not in invalid_report

    valid_findings = actual_gitleaks_findings(
        tmp_path / "valid",
        {path: valid_first + ";" + second + "\n"},
    )

    assert len(valid_findings) == 2
    assert {finding["RuleID"] for finding in valid_findings} == {
        owning_rule,
        companion_rule,
    }
    valid_owning_finding = next(
        finding for finding in valid_findings if finding["RuleID"] == owning_rule
    )
    valid_companion_finding = next(
        finding for finding in valid_findings if finding["RuleID"] == companion_rule
    )
    assert valid_owning_finding["Secret"] == "REDACTED"
    assert valid_owning_finding["Match"] != "REDACTED"
    assert valid_companion_finding["Secret"] == "REDACTED"
    assert valid_companion_finding["Match"] == "REDACTED"
    assert len(
        {
            (
                finding["File"],
                finding["StartLine"],
                finding["StartColumn"],
                finding["EndLine"],
                finding["EndColumn"],
            )
            for finding in valid_findings
        }
    ) == len(valid_findings)
    assert all(finding["Secret"] == "REDACTED" for finding in valid_findings)
    valid_report = json.dumps(valid_findings)
    assert valid_first.split("=", 1)[-1] not in valid_report
    assert second.split("=", 1)[-1] not in valid_report


@pytest.mark.parametrize(
    (
        "path",
        "unsafe_first",
        "safe_second",
        "safe_first",
        "unsafe_second",
        "owning_rule",
        "companion_rule",
    ),
    [
        pytest.param(
            "docs/adjacent.md",
            "customer." + "finance",
            "example." + "test",
            "example." + "test",
            "customer." + "technology",
            "bare-apex-domain",
            "adjacent-bare-apex-domain",
            id="bare-prose",
        ),
        pytest.param(
            "apps/domain-settings.py",
            "DOMAIN=customer." + "finance",
            "DOMAIN=docs.python." + "org",
            "DOMAIN=docs.python." + "org",
            "DOMAIN=customer." + "technology",
            "assigned-domain-name",
            "adjacent-assigned-domain-name",
            id="domain-assignments",
        ),
        pytest.param(
            "apps/network-settings.py",
            "HOST=customer." + "finance",
            "HOST=api.github." + "com",
            "HOST=api.github." + "com",
            "HOST=api.customer." + "com",
            "assigned-network-domain",
            "adjacent-assigned-network-domain",
            id="network-assignments",
        ),
    ],
)
def test_actual_gitleaks_apex_domain_companion_allows_only_safe_second_value(
    tmp_path: Path,
    path: str,
    unsafe_first: str,
    safe_second: str,
    safe_first: str,
    unsafe_second: str,
    owning_rule: str,
    companion_rule: str,
) -> None:
    """Whole-match allowances must inspect the second structural value."""
    safe_second_findings = actual_gitleaks_findings(
        tmp_path / "safe-second",
        {path: unsafe_first + ";" + safe_second + "\n"},
    )

    assert len(safe_second_findings) == 1
    assert {finding["RuleID"] for finding in safe_second_findings} == {
        owning_rule
    }
    assert companion_rule not in {
        finding["RuleID"] for finding in safe_second_findings
    }

    unsafe_second_findings = actual_gitleaks_findings(
        tmp_path / "unsafe-second",
        {path: safe_first + ";" + unsafe_second + "\n"},
    )

    assert len(unsafe_second_findings) == 1
    assert {finding["RuleID"] for finding in unsafe_second_findings} == {
        companion_rule
    }
    assert unsafe_second_findings[0]["Secret"] == "REDACTED"
    assert unsafe_second_findings[0]["Match"] == "REDACTED"
    unsafe_report = json.dumps(unsafe_second_findings)
    assert safe_first.split("=", 1)[-1] not in unsafe_report
    assert unsafe_second.split("=", 1)[-1] not in unsafe_report


MULTILINE_COMPANION_CASES = (
    pytest.param(
        "docs/multiline-adjacent.md",
        "tests/fixtures-synthetic",
        "docs",
        ".md",
        "",
        "",
        "bare-apex-domain",
        "adjacent-bare-apex-domain",
        id="bare-prose",
    ),
    pytest.param(
        "apps/multiline-domain-settings.py",
        "tests/fixtures-synthetic",
        "apps",
        ".py",
        "DOMAIN=",
        "PUBLIC_DOMAIN=",
        "assigned-domain-name",
        "adjacent-assigned-domain-name",
        id="domain-assignments",
    ),
    pytest.param(
        "apps/multiline-network-settings.py",
        "tests/fixtures-synthetic",
        "apps",
        ".py",
        "HOST=",
        "ORIGIN=",
        "assigned-network-domain",
        "adjacent-assigned-network-domain",
        id="network-assignments",
    ),
)


@pytest.mark.parametrize(
    (
        "path",
        "fixture_directory",
        "outside_directory",
        "extension",
        "first_prefix",
        "second_prefix",
        "owning_rule",
        "companion_rule",
    ),
    MULTILINE_COMPANION_CASES,
)
def test_gitleaks_apex_domain_multiline_companion_captures_exact_pair(
    path: str,
    fixture_directory: str,
    outside_directory: str,
    extension: str,
    first_prefix: str,
    second_prefix: str,
    owning_rule: str,
    companion_rule: str,
) -> None:
    """The complete-pair secret excludes both surrounding boundaries."""
    del path, fixture_directory, outside_directory, extension, owning_rule
    pair = (
        first_prefix
        + "customer."
        + "finance"
        + ";"
        + second_prefix
        + "portal."
        + "technology"
    )
    content = "fixture header\n" + pair + ")\n"
    rule = gitleaks_rule(companion_rule)

    match = re.search(str(rule["regex"]), content)

    assert match is not None
    assert match.group(int(rule["secretGroup"])) == pair


@pytest.mark.parametrize(
    (
        "path",
        "fixture_directory",
        "outside_directory",
        "extension",
        "first_prefix",
        "second_prefix",
        "owning_rule",
        "companion_rule",
    ),
    MULTILINE_COMPANION_CASES,
)
def test_gitleaks_apex_domain_multiline_companion_allows_safe_second(
    path: str,
    fixture_directory: str,
    outside_directory: str,
    extension: str,
    first_prefix: str,
    second_prefix: str,
    owning_rule: str,
    companion_rule: str,
) -> None:
    """Whole-file evaluation keeps second-slot allowances after a newline."""
    del path, fixture_directory, outside_directory, extension, owning_rule
    pair = (
        first_prefix
        + "customer."
        + "finance"
        + ";"
        + second_prefix
        + "docs.python."
        + "org"
    )

    assert gitleaks_rule_findings(
        gitleaks_rule(companion_rule), "fixture header\n" + pair + "\n"
    ) == []


@pytest.mark.parametrize(
    (
        "path",
        "fixture_directory",
        "outside_directory",
        "extension",
        "first_prefix",
        "second_prefix",
        "owning_rule",
        "companion_rule",
    ),
    MULTILINE_COMPANION_CASES,
)
@pytest.mark.parametrize(
    "safe_second_domain",
    ["example." + "test", "docs.python." + "org"],
    ids=["reserved-second", "canonical-second"],
)
def test_actual_gitleaks_apex_domain_multiline_companion_allows_safe_second(
    tmp_path: Path,
    path: str,
    fixture_directory: str,
    outside_directory: str,
    extension: str,
    first_prefix: str,
    second_prefix: str,
    owning_rule: str,
    companion_rule: str,
    safe_second_domain: str,
) -> None:
    """A preceding line must not defeat the second-slot safe-host allowance."""
    del fixture_directory, outside_directory, extension
    unsafe_domain = "customer." + "finance"
    pair = (
        first_prefix
        + unsafe_domain
        + ";"
        + second_prefix
        + safe_second_domain
    )

    findings = actual_gitleaks_findings(
        tmp_path,
        {path: "fixture header\n" + pair + "\n"},
    )

    assert len(findings) == 1
    assert [finding["RuleID"] for finding in findings] == [owning_rule]
    assert companion_rule not in {finding["RuleID"] for finding in findings}
    assert findings[0]["StartLine"] == 2
    assert findings[0]["Secret"] == "REDACTED"
    assert findings[0]["Match"] != "REDACTED"
    report = json.dumps(findings)
    assert unsafe_domain not in report
    assert safe_second_domain not in report


@pytest.mark.parametrize(
    (
        "path",
        "fixture_directory",
        "outside_directory",
        "extension",
        "first_prefix",
        "second_prefix",
        "owning_rule",
        "companion_rule",
    ),
    MULTILINE_COMPANION_CASES,
)
def test_actual_gitleaks_apex_domain_multiline_companion_dummy_cross_products(
    tmp_path: Path,
    path: str,
    fixture_directory: str,
    outside_directory: str,
    extension: str,
    first_prefix: str,
    second_prefix: str,
    owning_rule: str,
    companion_rule: str,
) -> None:
    """All DUMMY cross-products keep path AND second-slot semantics after headers."""
    del path
    first_domain = "customer." + "finance"
    second_domain = "portal." + "technology"
    dummy_first_domain = "DUMMY_" + first_domain
    dummy_second_domain = "DUMMY_" + second_domain
    value_pairs = {
        "dummy-dummy": (dummy_first_domain, dummy_second_domain),
        "dummy-non-dummy": (dummy_first_domain, second_domain),
        "non-dummy-dummy": (first_domain, dummy_second_domain),
        "non-dummy-non-dummy": (first_domain, second_domain),
    }
    files = {}
    for case_name, (first_value, second_value) in value_pairs.items():
        pair = (
            first_prefix
            + first_value
            + ";"
            + second_prefix
            + second_value
        )
        content = "fixture header\n" + pair + ")\n"
        files[f"{fixture_directory}/{case_name}{extension}"] = content
        files[f"{outside_directory}/multiline-{case_name}{extension}"] = content

    findings = actual_gitleaks_findings(tmp_path, files)
    findings_by_file: dict[str, list[str]] = {}
    for finding in findings:
        findings_by_file.setdefault(str(finding["File"]), []).append(
            str(finding["RuleID"])
        )

    expected_rules_by_file = {
        f"{fixture_directory}/dummy-non-dummy{extension}": [companion_rule],
        f"{fixture_directory}/non-dummy-dummy{extension}": [owning_rule],
        f"{fixture_directory}/non-dummy-non-dummy{extension}": [
            companion_rule,
            owning_rule,
        ],
        f"{outside_directory}/multiline-dummy-dummy{extension}": [
            companion_rule,
            owning_rule,
        ],
        f"{outside_directory}/multiline-dummy-non-dummy{extension}": [
            companion_rule,
            owning_rule,
        ],
        f"{outside_directory}/multiline-non-dummy-dummy{extension}": [
            companion_rule,
            owning_rule,
        ],
        f"{outside_directory}/multiline-non-dummy-non-dummy{extension}": [
            companion_rule,
            owning_rule,
        ],
    }

    assert len(findings) == 12
    assert {
        file_name: sorted(rule_ids)
        for file_name, rule_ids in findings_by_file.items()
    } == {
        file_name: sorted(rule_ids)
        for file_name, rule_ids in expected_rules_by_file.items()
    }
    assert f"{fixture_directory}/dummy-dummy{extension}" not in findings_by_file
    assert len(
        {
            (
                finding["File"],
                finding["StartLine"],
                finding["StartColumn"],
                finding["EndLine"],
                finding["EndColumn"],
            )
            for finding in findings
        }
    ) == len(findings)
    assert all(finding["StartLine"] == 2 for finding in findings)
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    assert all(
        finding["Match"] == "REDACTED"
        for finding in findings
        if finding["RuleID"] == companion_rule
    )
    assert all(
        finding["Match"] != "REDACTED"
        for finding in findings
        if finding["RuleID"] == owning_rule
    )
    report = json.dumps(findings)
    assert first_domain not in report
    assert second_domain not in report
    assert dummy_first_domain not in report
    assert dummy_second_domain not in report


def test_actual_gitleaks_network_companion_preserves_source_chain_allowance(
    tmp_path: Path,
) -> None:
    """A valid first network assignment must not make a source chain a host."""
    unsafe_domain = "customer." + "finance"
    findings = actual_gitleaks_findings(
        tmp_path,
        {
            "apps/network-settings.py": (
                "HOST=" + unsafe_domain + ";ORIGIN=location." + "origin\n"
            )
        },
    )

    assert len(findings) == 1
    assert findings[0]["RuleID"] == "assigned-network-domain"
    assert findings[0]["Secret"] == "REDACTED"
    assert unsafe_domain not in json.dumps(findings)


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
    assert sorted(
        (finding["StartLine"], finding["RuleID"]) for finding in findings
    ) == [
        (1, "bare-apex-domain"),
        (2, "bare-apex-domain"),
    ]
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
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
        (3, "assigned-production-endpoint"),
        (3, "non-example-domain"),
        (4, "bare-deployment-domain-docs-source"),
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
            "apps/source.py": (
                "api.logger.info\n" + deployment_domain + "\napi.client.get\n"
            ),
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
    ("path", "content", "owning_rule", "companion_rule"),
    [
        pytest.param(
            "docs/invalid-pair.md",
            "release." + "finance;portal.xn--ab-\n",
            "bare-apex-domain",
            "adjacent-bare-apex-domain",
            id="bare-prose",
        ),
        pytest.param(
            "apps/invalid-domain-pair.py",
            "DOMAIN=release." + "finance;PUBLIC_DOMAIN=portal.xn--ab-\n",
            "assigned-domain-name",
            "adjacent-assigned-domain-name",
            id="domain-assignments",
        ),
        pytest.param(
            "apps/invalid-network-pair.py",
            "HOST=release." + "finance;ORIGIN=portal.xn--ab-\n",
            "assigned-network-domain",
            "adjacent-assigned-network-domain",
            id="network-assignments",
        ),
    ],
)
def test_actual_gitleaks_domain_companions_do_not_truncate_invalid_second_value(
    tmp_path: Path,
    path: str,
    content: str,
    owning_rule: str,
    companion_rule: str,
) -> None:
    """The general sequence boundary must still reject a trailing-hyphen TLD."""
    findings = actual_gitleaks_findings(tmp_path, {path: content})

    assert len(findings) == 1
    assert findings[0]["RuleID"] == owning_rule
    assert companion_rule not in {finding["RuleID"] for finding in findings}


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
            "tests/fixtures-synthetic/first-dummy-only.md": (
                dummy_domains[0] + bare_separator + domains[1] + "\n"
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
            "tests/fixtures-synthetic/first-dummy-only.py": (
                "DOMAIN="
                + dummy_domains[0]
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
            "tests/fixtures-synthetic/first-dummy-only-network.py": (
                "HOST="
                + dummy_domains[0]
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
        "tests/fixtures-synthetic/first-dummy-only-network.py",
        "tests/fixtures-synthetic/first-dummy-only.md",
        "tests/fixtures-synthetic/first-dummy-only.py",
        "tests/fixtures-synthetic/non-dummy-network.py",
        "tests/fixtures-synthetic/non-dummy-network.py",
        "tests/fixtures-synthetic/non-dummy.md",
        "tests/fixtures-synthetic/non-dummy.md",
        "tests/fixtures-synthetic/non-dummy.py",
        "tests/fixtures-synthetic/non-dummy.py",
    ]
    assert {finding["RuleID"] for finding in findings} == expected_rules
    assert all(finding["Secret"] == "REDACTED" for finding in findings)
    assert all(
        finding["Match"] == "REDACTED"
        for finding in findings
        if str(finding["RuleID"]).startswith("adjacent-")
    )
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
