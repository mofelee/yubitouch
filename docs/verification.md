# YubiTouch v0.1 验证矩阵

本文档用于记录自动化无法覆盖的真实 macOS、YubiKey、1Password、LaunchAgent 和 SSH
客户端结果。每次发布候选版本使用新的矩阵副本或 Issue 评论，保留命令、版本和脱敏结论。
不得记录 PIN、PIN 长度、签名请求/结果、YubiKey 序列号、账户名或完整 secret reference。

## 自动化基线

```sh
make test
make test-race
make vet
make app
```

Unix socket、真实 `ssh-agent` 和 daemon 子进程生命周期测试在受限沙箱中可能明确跳过；
发布验证必须在普通本地终端再次运行，并记录实际执行而非 skip 的结果。

## 环境记录

使用以下命令采集非敏感版本信息：

```sh
sw_vers
uname -m
go version
yubitouch version
"$(brew --prefix openssh)/bin/ssh" -V
brew list --versions openssh yubico-piv-tool ykman
go list -m github.com/1Password/onepassword-sdk-go
```

| 日期 | macOS/build | 架构 | YubiTouch commit | OpenSSH | yubico-piv-tool | ykman | 1Password/SDK | 结果 |
|---|---|---|---|---|---|---|---|---|
| YYYY-MM-DD |  | arm64/amd64 |  |  |  |  |  | pending |

## YubiKey 与签名

1. 运行 `ykman piv keys info 9a`，记录算法和 PIN/touch policy，不记录序列号。
2. 按 README 导出 9A 公钥，完成 `configure`、`ensure` 和 SSH config 后运行 `doctor`。
3. 连续运行两次 `yubitouch test-sign`，确认每次真实签名都有独立触摸提示并成功关闭。
4. 在一个请求等待或进行中时移除设备，确认请求确定失败且 UI 给出失败状态。
5. 重新插入设备，重新运行一次 `test-sign`，确认下一次请求可按真实会话状态恢复。
6. 错误 PIN 测试只在已确认剩余尝试次数且有恢复方案的测试设备上执行；确认只尝试一次。

| 场景 | prompt | 1Password | 退出码 | UI | 重试次数 | 结果/Issue |
|---|---|---|---:|---|---:|---|
| 成功签名 | pending | pending | 0 | pending | 0 |  |
| PIN provider 用户取消 | pending | pending | 4 | pending | 0 |  |
| 客户端取消签名 | pending | pending | 6 | pending | 0 |  |
| 错误 PIN | pending | pending | 4 | pending | 0 |  |
| 触摸超时 | pending | pending | 6 | pending | 0 |  |
| 设备移除/重插 | pending | pending | 3 | pending | 0 |  |

1Password 模式另验证：桌面应用集成启用/禁用、Touch ID、用户取消、超时、错误账户和错误
reference。确认未安装 `op` CLI 时仍可工作，失败时不会回退到 prompt。

## LaunchAgent 与无副作用查询

1. 运行 `yubitouch ensure`，确认 plist 位于
   `~/Library/LaunchAgents/com.github.mofelee.yubitouch.plist`。
2. 运行 `launchctl print gui/$UID/com.github.mofelee.yubitouch`，记录 daemon PID。
3. 在 provider 尚未加载时运行：

   ```sh
   SSH_AUTH_SOCK="$HOME/.ssh/yubitouch/agent.sock" ssh-add -L
   yubitouch status --json
   ```

   确认只列出配置公钥，且没有 PIN、Touch ID、UI 或 backend provider 加载。
4. 对记录的 daemon PID 发送 `SIGKILL`，确认 launchd 拉起新 PID、公共 socket 恢复，随后重复
   identity 查询并确认仍无 provider 副作用。只操作该次 `launchctl print` 确认的 daemon PID。
5. 分别运行 `yubitouch reload`、`yubitouch stop` 和 `yubitouch ensure`，确认 socket/进程状态
   与命令语义一致，最终没有孤儿受管进程。

| 场景 | daemon PID 变化 | 公共 socket | backend/provider | PIN/UI 副作用 | 结果/Issue |
|---|---|---|---|---|---|
| 登录启动 |  |  | not loaded | none |  |
| daemon SIGKILL/KeepAlive |  |  | not loaded | none |  |
| reload |  |  | not loaded | none |  |
| stop/ensure |  |  | not loaded | none |  |

## SSH 与客户端矩阵

每个 OpenSSH/yubico-piv-tool 组合至少验证一次新连接、一次 ControlMaster 复用和一次关闭
master 后的新连接。使用测试主机别名，不在证据中记录真实主机名或用户名。

```sh
ssh -G example-yubikey >/dev/null
ssh -o ControlMaster=no example-yubikey true
ssh -M -S /tmp/yubitouch-control.sock -fN example-yubikey
ssh -S /tmp/yubitouch-control.sock example-yubikey true
ssh -S /tmp/yubitouch-control.sock -O exit example-yubikey
```

| 客户端 | 版本 | session-bind/SignWithFlags | 新连接 Touch | 复用无 Touch | 结果/Issue |
|---|---|---|---|---|---|
| Homebrew OpenSSH |  |  |  |  |  |
| DebianForm |  | n/a/observed |  |  |  |

DebianForm 只配置普通 SSH Host/IdentityAgent/IdentityFile，不安装 wrapper 或额外 hook。分别记录
新连接和应用自身连接复用的表现；`ssh -G`、DebianForm 配置解析和 identity list 均不得显示 UI。

## UI 与安全检查

在普通桌面、多 Space 和全屏应用中检查等待、成功、失败和超时状态。确认提示不抢焦点，
成功由签名结果关闭，设备移除显示失败，多个并发请求不会叠加窗口。

人工检查 `ps`、进程环境、`config.json`、`state.json`、诊断日志和运行目录中的文件名/内容。
只确认敏感字段不存在，不要把真实 PIN 作为 shell 搜索参数或保存检查输出。报告中只记录
“通过/失败 + Issue 链接”；发现泄漏时先停止测试并按敏感信息处理流程清理证据。
