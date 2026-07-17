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
mkdir -p ~/.local/bin
ln -s /Applications/YubiTouch.app/Contents/MacOS/yubitouch ~/.local/bin/yubitouch
```

正式发布还需要 Developer ID 签名和 notarization；当前构建脚本不会伪装已完成这些步骤。

## 配置

YubiTouch 将非敏感配置保存到 `~/.ssh/yubitouch/config.json`，文件权限为 `0600`，
目录权限为 `0700`。配置 schema 没有 PIN 字段；设置 `YUBITOUCH_PIN` 会被明确拒绝。

准备一个只包含 PIV 9A 身份公钥的 OpenSSH 公钥文件。不要使用 YKCS11 返回的 RSA
PIV Attestation key。

### 手动 PIN

```sh
export YUBITOUCH_PIN_PROVIDER=prompt
export YUBITOUCH_PUBLIC_KEY="$HOME/.ssh/yubikey-piv.pub"
yubitouch configure
yubitouch ensure
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
```

`YUBITOUCH_1PASSWORD_ACCOUNT` 可以是桌面应用显示的账户名或账户 UUID。v0.1 只支持
Desktop App Integration，不使用 service account token。SDK 返回不可变 Go `string`，
因此无法形式化保证原地清零；YubiTouch 把解析限制在一次性 AskPass helper 进程中，
写入 OpenSSH AskPass 管道后立即退出。

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
```

`status` 只通过 `ykman list --serials` 探测设备，并且只输出设备数量，不返回序列号。
设备状态为 `connected`、`not_detected` 或 `probe_unavailable`；该探测不会加载 YKCS11、
读取 PIN 或显示触摸提示。

`test-sign` 在 Agent 协议返回通用失败时，只读取 daemon 同步写入 `state.json` 的预定义
失败分类。设备不可用、PIN/provider 初始化、目标 key 不匹配、超时或取消分别映射到
退出码 `3`、`4`、`5`、`6`；未知分类返回 `1`。底层错误文本和被篡改的分类不会回显。

退出码：`0` 成功，`1` 运行错误，`2` 配置错误，`3` 设备不可用，`4` PIN provider
失败或取消，`5` 目标公钥不匹配，`6` 签名超时或取消。

## 安全边界

- 私钥和签名操作留在 YubiKey/YKCS11/OpenSSH 中。
- 公共 Agent 只列出配置的目标公钥，拒绝其他 key 的签名。
- 公共 Agent 拒绝 Add、Remove、RemoveAll、Lock 和 Unlock。
- 每个前端连接使用独立 backend Agent 连接；`session-bind@openssh.com` 上下文不会跨客户端共享。
- 同一时间只有一个 PIV 签名进入 backend；错误 PIN 不自动重试。
- PIN 不进入命令行参数、配置、普通环境变量、日志或状态文件。
- 签名请求和签名结果不会写入日志、状态文件或 UI。
- YubiTouch 不支持 Agent Forwarding，建议保持 `ForwardAgent no`。

YubiTouch 不能防御已经完全控制当前 macOS 用户或 root 的恶意软件，也不能消除用户触摸
期间同权限恶意进程抢用 Agent 的风险。

## 开发验证

自动化测试覆盖配置权限、禁止 PIN 字段、Agent key 过滤、受限操作、SignWithFlags、
session-bind 重放、每客户端 backend、签名串行化、超时、AskPass 一次性 guard、LaunchAgent
plist 和脱敏状态。真实 Unix socket 与 ssh-agent 生命周期测试在受限沙箱外运行。

发布前还必须在真实 YubiKey 上完成：PIV 9A/Attestation 过滤、错误 PIN 尝试次数、设备
拔插、Touch ID、OpenSSH 版本矩阵、DebianForm、全屏 Space、代码签名和 notarization。
