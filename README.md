# YubiTouch

YubiTouch 是一个面向 macOS、YubiKey PIV、YKCS11 和 OpenSSH 的本地 SSH Agent
代理。它在真正发生 PIV 签名时显示原生触摸提示，并在签名返回后自动关闭。

YubiTouch 是独立开源项目，与 Yubico 没有关联，也未获得 Yubico 的认可或背书。

> 当前状态：v0.1 开发版。Agent 代理、LaunchAgent、OpenSSH backend、AskPass、
> 1Password Go SDK、原生 UI 和诊断命令已经实现；发布签名、公证以及真实
> YubiKey/多版本 OpenSSH 兼容矩阵仍需完成。

## 工作方式

```text
ssh / DebianForm
       |
       v
~/.ssh/yubitouch/agent.sock
       |
       v
YubiTouch Agent proxy -- SignRequest --> PIN / provider lazy load
       |                                  |
       v                                  v
OpenSSH ssh-agent                     native touch panel
       |
       v
YKCS11 -> YubiKey PIV 9A -> touch -> signature
```

LaunchAgent 登录后只启动轻量 daemon 和公共 Agent socket。密钥列表查询直接返回
配置的 PIV 9A 公钥，不启动 backend、不读取 PIN，也不显示 UI。只有目标公钥的真实
`SignRequest` 才加载 YKCS11 provider。

触摸等待浮层提供取消按钮。按钮绑定到该次请求的内部 ID，只取消当前显示的请求；取消会
关闭该客户端的 backend 连接、立即关闭浮层且不自动重试，不会取消其他排队或后续请求。
标准 SSH Agent 协议只返回通用失败；`test-sign` 会从脱敏 state 分类为 canceled 并返回 6。

## 依赖

```sh
brew install openssh yubico-piv-tool ykman
```

1Password 模式还需要安装 1Password 桌面应用，并在 **Settings > Developer** 中启用
**Integrate with other apps**。按需在安全设置中启用 Touch ID。YubiTouch 使用官方
Go SDK，不依赖 `op` CLI。

构建需要 Go 1.25 或更高版本、Xcode Command Line Tools 和 CGO。

## 构建

```sh
make test
make test-race
make vet
make app
```

应用输出到 `dist/YubiTouch.app`。开发安装时应先把应用移动到稳定位置，再建立 CLI
入口并注册 LaunchAgent；移动已经注册的二进制会使 launchd 路径失效。

```sh
ditto dist/YubiTouch.app /Applications/YubiTouch.app
mkdir -p ~/.local/bin
ln -sfn /Applications/YubiTouch.app/Contents/MacOS/yubitouch ~/.local/bin/yubitouch
```

正式发布还需要 Developer ID 签名和 notarization；当前构建脚本不会伪装已完成这些步骤。

### Release candidate

Release 构建必须在目标架构的原生 macOS runner 上完成，因为 Cocoa 和 1Password SDK 使用
CGO。分别在 Apple Silicon (`arm64`) 和 Intel (`amd64`) runner 构建，不把单架构产物标记为
universal。正式构建要求干净 worktree、`v<version>` tag、Developer ID 和 notarytool profile：

```sh
CODESIGN_IDENTITY='Developer ID Application: Example (TEAMID)' \
NOTARY_PROFILE='yubitouch-notary' \
make release VERSION=0.1.0
```

输出目录为 `dist/release/<version>/<arch>/`，包含 `YubiTouch.app` zip、独立 CLI、
`SHA256SUMS`、`release.json` 和 release notes。未签名、未打 tag 的本地候选只能显式运行：

```sh
ALLOW_DIRTY=1 ALLOW_UNTAGGED=1 ALLOW_UNSIGNED=1 make release VERSION=0.1.0
```

未签名候选会固定 app 文件时间并使用无额外 zip metadata 的排序归档，可用于复现性比较；
Developer ID timestamp 和 notarization ticket 会使正式签名产物包含 Apple 服务生成的数据。

## 配置

YubiTouch 将非敏感配置保存到 `~/.ssh/yubitouch/config.json`，文件权限为 `0600`，
目录权限为 `0700`。配置 schema 没有 PIN 字段；设置 `YUBITOUCH_PIN` 会被明确拒绝。

### 准备 PIV 9A 公钥

先确认 9A 槽位算法与触摸策略，再通过项目实际使用的 YKCS11 provider 枚举公钥：

```sh
ykman piv keys info 9a
mkdir -p ~/.ssh
chmod 700 ~/.ssh
"$(brew --prefix openssh)/bin/ssh-keygen" -D "$(brew --prefix yubico-piv-tool)/lib/libykcs11.dylib"
"$(brew --prefix openssh)/bin/ssh-keygen" -D "$(brew --prefix yubico-piv-tool)/lib/libykcs11.dylib" | awk '$1 == "ssh-ed25519"' > ~/.ssh/yubikey-piv.pub
test "$(wc -l < ~/.ssh/yubikey-piv.pub)" -eq 1
chmod 644 ~/.ssh/yubikey-piv.pub
```

YubiTouch v0.1 要求该文件是 `ssh-ed25519` PIV 9A 公钥。不要使用 YKCS11 返回的 RSA
PIV Attestation key。第一条 `ssh-keygen -D` 命令应显示 9A 的 `PIV Authentication` 注释；
如果设备还有其他 ED25519 PIV key，停止并人工选择 9A 对应行，不要使用自动过滤结果。
`configure` 会拒绝其他算法或多行文件，`doctor` 会确认配置公钥出现在 provider 输出中并
报告被过滤的其他 key 数量。

### 手动 PIN

```sh
export YUBITOUCH_PIN_PROVIDER=prompt
export YUBITOUCH_PUBLIC_KEY="$HOME/.ssh/yubikey-piv.pub"
yubitouch configure
yubitouch ensure
yubitouch test-sign
```

第一次真实签名时显示 `NSSecureTextField` 对话框。图形会话不可用时尝试从当前 TTY
安全读取；两者都不可用时快速失败。

### 1Password

```sh
export YUBITOUCH_PIN_PROVIDER=1password
export YUBITOUCH_1PASSWORD_ACCOUNT='My Account'
export YUBITOUCH_1PASSWORD_REF='op://Personal/YubiKey PIV/pin'
export YUBITOUCH_PUBLIC_KEY="$HOME/.ssh/yubikey-piv.pub"
yubitouch configure
yubitouch ensure
yubitouch test-sign
```

`YUBITOUCH_1PASSWORD_ACCOUNT` 可以是桌面应用显示的账户名或账户 UUID。v0.1 只支持
Desktop App Integration，不使用 service account token。SDK 返回不可变 Go `string`，
因此无法形式化保证原地清零；YubiTouch 把解析限制在一次性 AskPass helper 进程中，
写入 OpenSSH AskPass 管道后立即退出。受 Go 垃圾回收、运行库复制和外部 SDK/OpenSSH
行为影响，任何模式都无法形式化证明内存中不存在残留副本。

在 1Password 模式下，`yubitouch doctor` 会本地校验 secret reference 语法，并初始化
Desktop App Integration client 来验证账户和桌面集成；这可能触发 1Password 自己的授权
界面，但不会解析或读取 PIN，也不会加载 YKCS11。只有显式 `yubitouch test-sign` 才会通过
一次性 AskPass helper 调用 `Secrets().Resolve`，验证引用存在性和完整授权链路。

其他支持的覆盖变量：

- `YUBITOUCH_CONFIG`
- `YUBITOUCH_YKCS11`
- `YUBITOUCH_OPENSSH_PREFIX`
- `YUBITOUCH_SOCKET`
- `YUBITOUCH_BACKEND_SOCKET`
- `YUBITOUCH_SOUND`
- `YUBITOUCH_SIGN_TIMEOUT`
- `YUBITOUCH_LOG_LEVEL`

修改环境变量后再次运行 `yubitouch configure`，然后运行 `yubitouch reload`。

`configure` 时的优先级为：当前环境变量、已有配置文件、内置默认值。除内部 daemon 的
`--config` 外，v0.1 没有配置字段的命令行覆盖。daemon 不读取交互式 shell 环境；它只读取
`ensure` 注册时确定的 `0600` 配置文件。`YUBITOUCH_CONFIG` 只选择配置文件位置，不写入文件。

| 配置字段 | 环境变量 | 默认值 |
|---|---|---|
| `pin_provider` | `YUBITOUCH_PIN_PROVIDER` | `prompt` |
| `onepassword_account` | `YUBITOUCH_1PASSWORD_ACCOUNT` | 1Password 模式必填 |
| `onepassword_ref` | `YUBITOUCH_1PASSWORD_REF` | 1Password 模式必填 `op://` reference |
| `public_key` | `YUBITOUCH_PUBLIC_KEY` | 必填 |
| `ykcs11` | `YUBITOUCH_YKCS11` | Homebrew `opt/yubico-piv-tool` 自动检测 |
| `openssh_prefix` | `YUBITOUCH_OPENSSH_PREFIX` | Homebrew `opt/openssh` 自动检测 |
| `socket` | `YUBITOUCH_SOCKET` | `~/.ssh/yubitouch/agent.sock` |
| `backend_socket` | `YUBITOUCH_BACKEND_SOCKET` | `~/.ssh/yubitouch/backend.sock` |
| `sound` | `YUBITOUCH_SOUND` | `Glass`；`none` 静音 |
| `sign_timeout` | `YUBITOUCH_SIGN_TIMEOUT` | `60s` |
| `log_level` | `YUBITOUCH_LOG_LEVEL` | `info` |

`yubitouch ensure` 原子写入 `~/Library/LaunchAgents/com.github.mofelee.yubitouch.plist`，然后
bootstrap 或 kickstart 当前 GUI 用户的 LaunchAgent。plist 使用 `RunAtLoad` 和 `KeepAlive`；
登录启动、`ensure` 和 `reload` 都只恢复 daemon/公共 socket，不加载 provider。

## 诊断日志

daemon 将有界 JSONL 日志写入 `~/.ssh/yubitouch/yubitouch.log`，权限固定为 `0600`。
日志达到约 1 MiB 后会在原文件内重置，避免后台服务无限占用磁盘。`log_level` 支持：

- `error`：只记录失败和超时分类。
- `info`：额外记录 daemon 生命周期与签名结果，默认值。
- `debug`：额外记录 provider 初始化和等待触摸状态。

日志接口只接受预定义事件和失败分类，不接受任意错误字符串。PIN、PIN 长度、签名请求、
签名结果、远程主机和完整 1Password secret reference 均不会写入日志。`yubitouch status`
显示日志路径、权限和大小；`yubitouch doctor` 会检查日志是否为普通的 `0600` 文件。

## SSH 配置

SSH 配置只指向标准 Agent socket，不需要 wrapper 或 `Match exec`：

```sshconfig
Host example-yubikey
    HostName server.example.com
    User your-user
    IdentityAgent ~/.ssh/yubitouch/agent.sock
    IdentityFile ~/.ssh/yubikey-piv.pub
    IdentitiesOnly yes
    ForwardAgent no
    ControlMaster no
```

多个主机可以使用普通 SSH pattern：

```sshconfig
Host production-* bastion
    IdentityAgent ~/.ssh/yubitouch/agent.sock
    IdentityFile ~/.ssh/yubikey-piv.pub
    IdentitiesOnly yes
    ForwardAgent no
```

读取 SSH config 的第三方程序可直接使用同一 socket。`ssh -G`、密钥列表查询以及没有
新签名的 ControlMaster 复用不会请求 PIN 或显示触摸提示。

### DebianForm

DebianForm 无需 YubiTouch wrapper 或专用集成。让它继续使用系统 SSH 配置，并让目标 Host
匹配上面的 `IdentityAgent`、`IdentityFile` 和 `IdentitiesOnly` 即可。DebianForm 发起新的
SSH 签名时会出现触摸提示；复用已有连接而没有新签名时不显示提示是预期行为。

完成本地验证后可直接测试配置与登录：

```sh
yubitouch doctor
ssh -G example-yubikey >/dev/null
ssh example-yubikey
```

## 命令

```text
yubitouch configure       校验并保存非敏感配置
yubitouch ensure          检查或注册 LaunchAgent，不加载 provider
yubitouch status          显示脱敏状态
yubitouch status --json   输出稳定的机器可读状态
yubitouch reload          重启服务并读取新配置
yubitouch stop            停止当前用户的 LaunchAgent
yubitouch doctor          检查依赖、权限、socket 和配置
yubitouch test-sign       显式运行 PIN、触摸和签名全链路
yubitouch about           显示项目身份及无关联声明
yubitouch version         显示版本和提交信息
```

`status` 只通过 `ykman list --serials` 探测设备，并且只输出设备数量，不返回序列号。
设备状态为 `connected`、`not_detected` 或 `probe_unavailable`；该探测不会加载 YKCS11、
读取 PIN 或显示触摸提示。

`test-sign` 在 Agent 协议返回通用失败时，只读取 daemon 同步写入 `state.json` 的预定义
失败分类。设备不可用、PIN/provider 初始化、目标 key 不匹配、超时或取消分别映射到
退出码 `3`、`4`、`5`、`6`；未知分类返回 `1`。底层错误文本和被篡改的分类不会回显。

退出码：`0` 成功，`1` 运行错误，`2` 配置错误，`3` 设备不可用，`4` PIN provider
失败或取消，`5` 目标公钥不匹配，`6` 签名超时或取消。

## 故障排查

| 现象 | 检查与处理 |
|---|---|
| `not configured` | 设置必要环境变量并重新运行 `yubitouch configure`。 |
| 公共 Agent socket 不可达 | 运行 `yubitouch ensure`，再检查 `yubitouch status` 与诊断日志。 |
| `doctor` 报告 YubiKey 不可用 | 重新插入设备，确认 `ykman list` 可见后重试。 |
| PIV 9A key 不匹配 | 重新执行 9A 公钥导出；不要选择 RSA Attestation key。 |
| prompt PIN 被取消或不可显示 | 在 Aqua 图形会话重试；TTY fallback 也不可用时不会后台等待。 |
| 1Password 初始化失败 | 解锁桌面应用，启用 Integrate with other apps，检查 account/reference 后重新 `configure`。 |
| 签名超时 | 保持设备连接，在提示出现后触摸；YubiTouch 不会自动重试该请求。 |
| 配置或路径修改后行为未变化 | 重新 `configure`，再运行 `yubitouch reload`。 |
| stale socket/backend 错误 | 先 `yubitouch stop`，确认受管服务停止后再 `yubitouch ensure`；不要手工杀死未知 agent。 |

`status --json` 适合采集脱敏状态，`doctor` 适合检查依赖与配置，`test-sign` 是唯一显式运行
完整 PIN/provider/touch 链路的诊断命令。错误详情按预定义分类记录在
`~/.ssh/yubitouch/yubitouch.log`，不应通过开启日志来寻找 PIN 或签名内容。

## 安全边界

- 私钥和签名操作留在 YubiKey/YKCS11/OpenSSH 中。
- 公共 Agent 只列出配置的目标公钥，拒绝其他 key 的签名。
- 公共 Agent 拒绝 Add、Remove、RemoveAll、Lock 和 Unlock。
- 每个前端连接使用独立 backend Agent 连接；`session-bind@openssh.com` 上下文不会跨客户端共享。
- 同一时间只有一个 PIV 签名进入 backend；错误 PIN 不自动重试。
- UI 取消、客户端断开和超时会关闭当前 backend 连接；旧请求的取消信号不能作用于下一条请求。
- 公共 Agent frame 在 payload 分配前限制为 1 MiB；`session-bind` 另限制为 16 条和累计 1 MiB。
- backend 尚未建立时仅接受并缓存 `session-bind`；其他 extension 返回标准 unsupported，不触发 backend/PIN/UI。
- PIN 不进入命令行参数、配置、普通环境变量、日志或状态文件。
- 签名请求和签名结果不会写入日志、状态文件或 UI。
- YubiTouch 不支持 Agent Forwarding，建议保持 `ForwardAgent no`。

YubiTouch 不能防御已经完全控制当前 macOS 用户或 root 的恶意软件，也不能消除用户触摸
期间同权限恶意进程抢用 Agent 的风险。

## 故障恢复

受管 `ssh-agent` 异常退出或 backend socket 消失时，下一次签名会在同一次健康检查中重启
YubiTouch 自己持有进程句柄的 agent。已经连接的前端客户端会在签名前通过只读 identity
查询检测失效连接，重建独立 backend 连接，并重放该客户端的 `session-bind@openssh.com`
上下文。绑定数据只保存在内存中，限制为 16 条和 1 MiB，并在连接关闭时尽力清零。

YubiTouch 不自动重试已经发给 backend 的签名，因为响应丢失时无法证明签名没有成功；
这样可以避免重复签名和错误 PIN 重试。无法验证为当前 Manager 启动的进程不会被终止。

每个公共 Agent 客户端都有独立的可取消 context。Unix socket HUP/EOF 会取消该客户端：
仍在全局队列中的请求直接丢弃，不启动签名且不覆盖当前触摸 UI；已经开始的请求停止等待、
关闭该客户端的 backend 连接并显示失败状态，但不会自动重试底层签名。

`status` 只有在公共 socket 可达且 `state.json` 记录的 daemon PID 仍存活时，才把 provider
状态视为当前状态。崩溃遗留文件会报告 `state_stale: true` 和 `provider_state: unavailable`，
不会展示陈旧 PID；最后签名事件和时间仅作为历史信息保留。状态检查不会主动终止 PID。
daemon 重启时会替换不可达的陈旧公共 socket；如果 backend socket 仍由可达进程监听，
新 Manager 会将其视为未受管资源并拒绝接管或终止。

配置保存 Homebrew 的稳定 `opt/yubico-piv-tool/lib/libykcs11.dylib` 路径，每次加载 provider
前重新解析当前实际 dylib。旧开发版写入的 Apple Silicon/Intel Cellar 版本路径会在读取时
规范化回 opt 路径，下一次 `configure` 会持久化迁移，因此 Homebrew 升级不会固定到旧版本。

## 开发验证

自动化测试覆盖配置权限、禁止 PIN 字段、Agent key 过滤、受限操作、SignWithFlags、
session-bind 重放、每客户端 backend、签名串行化、超时、AskPass 一次性 guard、LaunchAgent
plist 和脱敏状态。子进程崩溃测试还覆盖公共 socket 恢复、无副作用 identity 查询和 daemon
状态 PID 更新；跨 Manager 测试覆盖可达 backend 的归属边界。真实 Unix socket 与 ssh-agent
生命周期测试在受限沙箱外运行。

真实硬件、LaunchAgent、OpenSSH/ykcs11 版本、ControlMaster 和 DebianForm 的验证步骤与
记录模板见 [`docs/verification.md`](docs/verification.md)。更新矩阵时必须记录版本和结果，
不得附加 PIN、签名内容、设备序列号、账户名或完整 secret reference。

发布前还必须完成真实签名、错误 PIN 尝试次数、设备拔插、Touch ID、OpenSSH 版本矩阵、
DebianForm、全屏 Space、代码签名和 notarization 验收。
