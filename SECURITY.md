# Security Policy

## Supported versions

The public repository is currently establishing its initial foundation. No release version is supported yet.

## Reporting a vulnerability

Do not open a public issue that includes credentials, private URLs, IP addresses, recordings, transcripts, personal data, or exploit details that could put deployments at risk.

Use the project's private vulnerability-reporting channel when one is published. Until then, contact the repository maintainer through an established private channel and include only the minimum information needed to coordinate a secure report.

## Security expectations for contributions

- Never commit secrets, signing materials, private keys, databases, user content, or production configuration.
- Keep examples synthetic and use reserved example-only values.
- Do not add endpoints that access private, loopback, link-local, or cloud-metadata addresses without explicit SSRF protections and tests.
- Treat generated test fixtures as public: include only synthetic data and record their SHA-256 values in `tests/fixtures-synthetic/MANIFEST.sha256`.
- Prefix dummy secret-shaped fixture values with `DUMMY_` and keep them under `tests/fixtures-synthetic/`; no other secret allowlisting is accepted.
- Run the test suite, Ruff, the public-tree audit, and Gitleaks before requesting review. CI blocks changes when any gate fails and performs dependency review on pull requests.

Use the same local audit entry point as CI:

```bash
uv run pytest
uv run ruff check .
uv run python scripts/audit_public_tree.py .
uv run python scripts/audit_public_tree.py . --history HEAD
gitleaks git --redact --log-opts=HEAD --config .gitleaks.toml
gitleaks git --redact --log-opts=HEAD --config .gitleaks-paths.toml
```

Security-sensitive changes require review before publication.
