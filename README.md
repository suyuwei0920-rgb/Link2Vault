# Link2Vault

Link2Vault（链接入库）是由来科技打造的单用户、自托管工具，面向把链接和录音整理为 Markdown 知识库的个人用户。

本仓库从全新的 Git 历史建立，只包含可公开、可复现的通用源代码、文档、示例和合成测试夹具。它不包含任何真实用户内容、生产部署信息、凭据、签名材料或私有知识库。

## Project status

Phase 1 provides a reviewed public foundation: a minimal `/healthz` API,
repository and secret-scanning gates, and a hardened Docker Compose/Caddy
deployment boundary. Link ingestion, transcription, provider integrations, and
knowledge-vault workflows are not implemented yet.

For the supported Ubuntu 22.04/24.04 deployment contract and local validation
commands, see the [Docker installation guide](docs/install/docker.md).

## Public-boundary policy

Before contributing files, read [the public/private boundary](docs/public-boundary.md). In particular:

- Use synthetic fixtures only, and record each generated fixture's SHA-256 in `tests/fixtures-synthetic/MANIFEST.sha256`.
- Do not commit credentials, recordings, transcripts, Obsidian vaults, production endpoints, user-specific paths, databases, signed binaries, or private deployment files.
- Use generic example values such as `example.invalid`; do not reuse real configuration values in documentation, tests, or screenshots.

## License and notices

Link2Vault is licensed under [Apache License 2.0](LICENSE). See [NOTICE](NOTICE)
and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for attribution and the
current direct-dependency inventory.

## Security

Please read [SECURITY.md](SECURITY.md) before reporting a vulnerability or contributing security-sensitive changes.
