# Public/private boundary

Link2Vault is a fresh public repository for reusable, self-hosted software. Every added file must pass this boundary before it is tracked. This policy applies to source, documentation, test data, screenshots, generated artifacts, and Git history.

## Allowlist

| Path or file type | Permitted public content | Conditions |
| --- | --- | --- |
| `apps/` | Generic API, web, and mobile source code | Remove production coupling and user-specific paths. |
| `packages/` | Reusable libraries and provider adapters | No embedded credentials, production endpoints, or private datasets. |
| `deploy/docker/` | Self-hosted Docker examples | Use placeholders and an `.env.example`; exclude production overrides. |
| `docs/` | Installation, operations, security, and product documentation | Use generic/example-only values and synthetic screenshots. |
| `.github/` | Public CI, issue, and release configuration | Never include deploy credentials or production targets. |
| `tests/fixtures-synthetic/` | Generated synthetic fixtures | Every fixture SHA-256 must be recorded in `tests/fixtures-synthetic/MANIFEST.sha256`. |
| Legal files | `LICENSE`, `NOTICE`, and third-party notices | Keep license and attribution information accurate. |
| Manifests | Dependency, package, and SBOM manifests | Review generated content for secrets and private paths. |
| Lockfiles | Reproducible public dependency lockfiles | Keep only dependencies used by public code. |

## Denylist

| File, path, or value | Why it must stay private |
| --- | --- |
| `.git` from the donor project | It can expose historical content and credentials. |
| `.env` and environment-specific secret files | They can contain credentials and deployment configuration. |
| `.data` and runtime data | They can contain user content, task state, or databases. |
| Production files under `deploy/` | They can disclose operational topology and access details. |
| `obsidian_vault` | It is a private knowledge base and may contain personal or customer data. |
| `outputs` | Generated results can include user content or internal paths. |
| `proofreading` | It can contain private source material or editing history. |
| `releases` | It can contain private distribution artifacts or release history. |
| Static APKs | Public builds must be rebuilt by public CI with a new release identity. |
| Signing files | Keystores, certificates, provisioning files, and private keys are never public. |
| Production endpoint strings | Domains, IP addresses, buckets, and private service routes are operationally sensitive. |
| User-specific absolute paths | They disclose local identities and are not portable. |

## Review gate

1. Add files from the allowlist one at a time; do not copy repository history or broad directories.
2. Confirm every example, fixture, screenshot, and generated artifact is synthetic or generic.
3. Search staged content for secrets, production endpoint strings, and absolute paths before committing.
4. Keep the donor project, its `.git` directory, real data, credentials, and production deployment material outside this repository.

If a file does not clearly fit the allowlist, keep it private until it has been reviewed.
