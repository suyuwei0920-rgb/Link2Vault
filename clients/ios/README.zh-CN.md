# iPhone 快捷指令（实验版）

公开仓库不提供预签名 `.shortcut` 文件，因为该文件必须由 Apple
Shortcuts/iCloud 生成和签名。下面的步骤会在你的 iPhone 本地保存服务器地址和设备令牌。

1. 在 Link2Vault 管理端创建一个五分钟有效的一次性注册码。
2. 新建快捷指令 `Link2Vault Capture`，第一次运行时询问服务器 HTTPS 地址和注册码。
3. 使用“获取 URL 内容”向 `/ingest/enroll` 发送 JSON：`{"code":"注册码"}`。
4. 将响应中的设备令牌保存到快捷指令本地文件；不要写入 URL、备注或截图。
5. 后续运行时读取剪贴板，把完整抖音分享文字作为 `share_text` POST 到 `/ingest/links`。
6. 请求头添加 `Authorization: Bearer 设备令牌`，显示服务器返回的任务编号或错误信息。
7. 在“设置 → 辅助功能 → 触控 → 轻点背面”中，把轻点两下绑定到该快捷指令。

服务器返回 401 时删除本地令牌，并使用新的五分钟注册码重新注册。
