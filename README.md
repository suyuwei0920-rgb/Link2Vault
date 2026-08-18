# Link2Vault

Link2Vault（链接入库）是由来科技打造的单用户、自托管工具，面向把链接和录音整理为 Markdown 知识库的个人用户。

本仓库从全新的 Git 历史建立，只包含可公开、可复现的通用源代码、文档、示例和合成测试夹具。它不包含任何真实用户内容、生产部署信息、凭据、签名材料或私有知识库。

## 项目状态：0.1 实验版

当前版本已经包含一条可运行的单用户链路：

- iPhone 快捷指令提交抖音分享文字，或手机上传录音；
- 服务端持久化任务、断点续跑，并通过受限重定向解析和下载单条抖音视频；
- 腾讯云录音文件识别在调用前查询资源包，优先免费包、其次已购 2.0 包，余额不足或查询失败时停止，不自动进入后付费；
- DeepSeek 对逐字稿做保守语义清洗，同时保留不可变的原始逐字稿；
- 结果按日期写入 Obsidian 兼容的 Markdown 目录，并可通过 Bark 或 Webhook 通知；
- 提供设备一次性注册、撤销、任务历史、重试、删除、导出、备份和只增不删的 Obsidian 同步脚本。

实验边界：抖音页面策略可能变化，部分视频可能需要登录状态；博主主页最近
30 天批量采集仍是默认关闭的实验功能；Android 原生分享客户端尚未发布，
小米手机可先使用浏览器上传页或直接调用录音上传接口。项目面向个人自托管，
不是多租户 SaaS。

For the supported Ubuntu 22.04/24.04 deployment contract and local validation
commands, see the [Docker installation guide](docs/install/docker.md).

iPhone 设置见 `clients/ios/`，Obsidian 的 rsync、Syncthing、备份与恢复说明见
`docs/operations/`。

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
