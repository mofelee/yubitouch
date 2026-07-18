# YubiTouch

YubiTouch 是一个面向 macOS、YubiKey PIV、YKCS11 和 OpenSSH 的本地 SSH Agent
代理。它在真正发生 PIV 签名时显示原生触摸提示，并在签名返回后自动关闭。

YubiTouch 是独立开源项目，与 Yubico 没有关联，也未获得 Yubico 的认可或背书。

> 当前状态：v0.1 源码构建版。Agent 代理、LaunchAgent、OpenSSH backend、AskPass、
> 1Password Go SDK、原生 UI 和主要真实环境兼容性验证已经完成。项目只支持用户从可信
> 源码在本机完成构建与安装，不计划提供预编译应用、Developer ID 签名/公证或 Homebrew 包。

<p align="center">
  <img src="docs/images/touch-notification.webp" alt="YubiTouch SSH 签名触摸提醒" width="760">
</p>
<p align="center"><sub>真实签名请求会显示请求方、YubiTouch 和当前触摸状态。</sub></p>

## 安装与首次使用

项目不提供预编译安装包。请只从你信任的源码 checkout 在本机构建。下面是从一把未配置
的 YubiKey 到首次 SSH 登录的完整步骤。

### 1. 安装依赖

要求 macOS 13 或更高版本、YubiKey 5.7 或更高固件、Go 1.25 或更高版本，以及 Xcode
Command Line Tools。PIV 的 ED25519 支持从 YubiKey 5.7 开始，OpenSSH 的 ED25519
PKCS#11 支持从 10.1 开始。这里安装的 Homebrew OpenSSH 是 YubiTouch 后端
`ssh-agent`、`ssh-add` 和 `ssh-keygen -D` 的依赖，不要求把日常使用的 SSH 客户端换成
Homebrew 版本。

```sh
xcode-select -p
brew install go openssh yubico-piv-tool ykman

ykman --version
"$(brew --prefix openssh)/bin/ssh" -V
```

如果 `xcode-select -p` 失败，先运行 `xcode-select --install` 并完成 Apple 的安装界面。

普通连接可以继续使用 macOS 自带的 `/usr/bin/ssh`，无需调整 `PATH` 中 `ssh` 的优先级；
Apple OpenSSH 10.3p1 已完成真实签名登录验证。YubiTouch 会根据配置直接定位 Homebrew
后端工具。以后 Apple 更新系统 OpenSSH 时，仍建议先运行 `yubitouch test-sign` 和一次真实
SSH 登录再确认兼容性。

1Password 模式还需要 1Password 桌面应用。在 **Settings > Developer** 中启用
**Integrate with other apps**，并按需启用 Touch ID。YubiTouch 使用 1Password Go SDK，
不需要 `op` CLI。

### 2. 配置 YubiKey PIV 9A

这一节会修改 YubiKey。开始前必须有备用登录方式，例如第二把 key、云主机控制台或另一
个管理员账号。不要猜 PIN；错误 PIN 会消耗设备的有限重试次数。

先检查固件、PIV 状态和 9A 槽位：

```sh
ykman info
ykman piv info
ykman piv keys info 9a
```

如果 9A 已有重要密钥，立即停止，不要执行下面的生成或导入命令。`ykman piv reset` 会
清空整个 PIV 应用中的密钥和证书，YubiTouch 的安装不需要运行它。

全新的 PIV 应先修改默认 PIN、PUK 和 Management Key。下面的命令会交互式读取旧值和
新值，不要把这些值写进命令行参数：

```sh
ykman piv access change-pin
ykman piv access change-puk
ykman piv access change-management-key \
  --algorithm AES192 \
  --generate \
  --protect \
  --touch
```

把新 PIN 和 PUK 分开保存在可靠的密码管理器或离线恢复记录中。受 PIN 保护的随机
Management Key 留在 YubiKey 内，`--touch` 使后续 PIV 管理操作也需要触摸。

推荐直接在 YubiKey 内生成新的 ED25519 私钥。私钥从不离开设备：

```sh
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

piv_public_key="$HOME/.ssh/yubikey-piv-9a.pem"

ykman piv keys generate \
  --algorithm ED25519 \
  --pin-policy ONCE \
  --touch-policy ALWAYS \
  9a "$piv_public_key"

ykman piv certificates generate \
  --subject "CN=SSH PIV Authentication" \
  --valid-days 3650 \
  9a "$piv_public_key"

ykman piv keys info 9a
```

最终元数据必须显示 `Algorithm: ED25519`、`PIN required for use: ONCE` 和
`Touch required for use: ALWAYS`。PIN 策略只在生成或导入时设置；如果 Touch 显示为
`NEVER`，不能原地修改，必须在确认恢复路径后重新写入 9A。

如果必须保持现有 SSH 公钥，可以把现有 ED25519 私钥以加密 PKCS#8 形式导入 9A：

```sh
ykman piv keys import \
  --pin-policy ONCE \
  --touch-policy ALWAYS \
  9a /path/to/encrypted-ed25519-pkcs8.pem

ykman piv certificates import \
  9a /path/to/ssh-piv-certificate.pem
```

私钥转换、证书创建、指纹核对和迁移文件清理可参考
[macOS 使用 YubiKey PIV + YKCS11 保护现有 SSH 密钥](https://gist.github.com/mofelee/e4ececb2f1512b4c5bb588a45a08d1bc)
的第 5 至 9 节。`ykman` 5.9.2 的 ED25519 `--verify` 存在已知缺口，导入证书时不要添加
该参数。导入方案中的原始私钥副本仍可绕过 YubiKey；只有确认备用和恢复路径后才能处理
这些副本。Gist 后续的自建 Agent、`Match exec` 和通知脚本已由 YubiTouch 取代，不要安装。

通过项目实际使用的 YKCS11 provider 导出 SSH 公钥：

```sh
provider="$(brew --prefix yubico-piv-tool)/lib/libykcs11.dylib"
ssh_keygen="$(brew --prefix openssh)/bin/ssh-keygen"

"$ssh_keygen" -D "$provider"
"$ssh_keygen" -D "$provider" |
  awk '$1 == "ssh-ed25519"' > "$HOME/.ssh/yubikey-piv.pub"

test "$(wc -l < "$HOME/.ssh/yubikey-piv.pub")" -eq 1
chmod 600 "$HOME/.ssh/yubikey-piv.pub"
"$ssh_keygen" -lf "$HOME/.ssh/yubikey-piv.pub"
```

YKCS11 通常还会列出 RSA PIV Attestation key；它不是 SSH 登录 key，不要删除 F9
Attestation 槽位。如果行数检查失败，说明存在多个或没有 ED25519 key，请删除错误的
`yubikey-piv.pub` 并人工选择注释为 `PIV Authentication` 的 9A 公钥。

使用已有且可信的登录方式，把 `~/.ssh/yubikey-piv.pub` 加入每台目标服务器对应账户的
`~/.ssh/authorized_keys`。服务器只需要公钥，不要复制私钥。导入原有 SSH 私钥且指纹完全
一致时，服务器已有的公钥无需修改。

### 3. 构建并安装 YubiTouch

```sh
git clone https://github.com/mofelee/yubitouch.git
cd yubitouch

make test
make vet
make app

ditto dist/YubiTouch.app /Applications/YubiTouch.app
mkdir -p "$HOME/.local/bin"
ln -sfn /Applications/YubiTouch.app/Contents/MacOS/yubitouch \
  "$HOME/.local/bin/yubitouch"
export PATH="$HOME/.local/bin:$PATH"
yubitouch version
```

应用必须先放到稳定位置，再注册 LaunchAgent。注册后移动或删除应用会使登录启动路径失效。
把 `export PATH="$HOME/.local/bin:$PATH"` 保留在 `~/.zprofile` 后，重启终端也可以直接运行
`yubitouch`，无需设置临时 `$YT` 变量。

`yubitouch version` 中的十六进制值是构建时的 Git commit，不是每次 `make app` 都会变化的
构建序号。同一个 commit 重新构建仍会显示同一个值；可以用 `git rev-parse --short=12 HEAD`
核对。该命令只验证磁盘上的 CLI，不能证明已经运行的 LaunchAgent daemon 已经重启。
首次安装请继续完成下一步的 `configure` 和 `ensure`；覆盖已有安装时请使用下文“从源码
更新”的停服、复制和重新启动顺序。

### 4. 配置 PIN 来源并启动服务

YubiTouch 只把非敏感配置保存到 `~/.ssh/yubitouch/config.json`。不要设置
`YUBITOUCH_PIN`；PIN 不会保存在配置、环境变量、命令行或日志中。

选择一种 PIN 来源并保存配置，只执行下面两组命令中的一组。

使用系统安全输入框：

```sh
YUBITOUCH_PIN_PROVIDER=prompt \
YUBITOUCH_PUBLIC_KEY="$HOME/.ssh/yubikey-piv.pub" \
yubitouch configure
```

<p align="center">
  <img src="docs/images/piv-pin-prompt.webp" alt="YubiTouch 系统安全 PIN 输入框" width="560">
</p>
<p align="center"><sub>系统安全输入框模式：PIN 只用于加载 PIV provider，不会保存。</sub></p>

使用 1Password Desktop App Integration：

```sh
YUBITOUCH_PIN_PROVIDER=1password \
YUBITOUCH_1PASSWORD_ACCOUNT='My Account' \
YUBITOUCH_1PASSWORD_REF='op://Personal/YubiKey PIV/pin' \
YUBITOUCH_PUBLIC_KEY="$HOME/.ssh/yubikey-piv.pub" \
yubitouch configure
```

使用 1Password 时，先创建保存 PIV PIN 的字段，并复制该字段的 `op://` secret
reference。`YUBITOUCH_1PASSWORD_ACCOUNT` 可以是 1Password 显示的账户名或账户 UUID；
配置文件保存 reference，不保存其指向的 PIN。

<p align="center">
  <img src="docs/images/onepassword-authorization.webp" alt="1Password 授权 YubiTouch 读取 PIN" width="680">
</p>
<p align="center"><sub>1Password 模式：由桌面应用授权读取 PIN，不显示系统 PIN 输入框。</sub></p>

上述环境变量只在执行 `configure` 时使用。配置保存后，登录启动的 daemon 直接读取配置
文件，不依赖 shell 环境变量。随后注册当前 GUI 用户的 LaunchAgent 并验收：

```sh
yubitouch ensure
yubitouch doctor
yubitouch status
yubitouch test-sign
```

`ensure` 创建 `~/Library/LaunchAgents/com.github.mofelee.yubitouch.plist`。重新登录后服务会
自动恢复公共 Agent socket，但不会提前读取 PIN、调用 1Password 或加载 YKCS11。只有
`test-sign` 或 SSH 的真实签名请求才会加载 provider。

`test-sign` 成功时会输出：

```text
Test signature succeeded. Signature data was not retained.
```

### 5. 配置并使用 SSH

在 `~/.ssh/config` 中让目标主机使用公共 Agent socket 和 PIV 公钥：

```sshconfig
Host example-yubikey
    HostName server.example.com
    User your-user
    IdentityAgent ~/.ssh/yubitouch/agent.sock
    IdentityFile ~/.ssh/yubikey-piv.pub
    IdentitiesOnly yes
    ForwardAgent no
    ControlMaster auto
    ControlPersist 10m
    ControlPath ~/.ssh/yubitouch-%C.sock
```

之后直接运行 `ssh example-yubikey`。首次建立连接会请求 PIN 或 1Password 授权，并显示
YubiKey 触摸提示；复用已有 `ControlMaster` 连接时不会产生新签名，因此没有 UI。

下面的 `ssh` 可以是 macOS 自带的 `/usr/bin/ssh`，也可以是 Homebrew OpenSSH；只有
YubiTouch 管理的后端固定使用 Homebrew OpenSSH。

检查 OpenSSH 最终采用的配置并连接：

```sh
ssh -G example-yubikey |
  awk '$1 ~ /^(identityagent|identityfile|identitiesonly|forwardagent|controlmaster|controlpath|controlpersist)$/ {print}'

ssh example-yubikey
```

需要强制进行一次新签名时，先关闭复用的 master：

```sh
ssh -O exit example-yubikey
ssh example-yubikey
```

跳板和目标都接受同一 PIV key 时可以直接使用 ProxyJump：

```sshconfig
Host bastion
    HostName bastion.example.com
    User your-user

Host internal-target
    HostName target.internal
    User your-user
    ProxyJump bastion

Host bastion internal-target
    IdentityAgent ~/.ssh/yubitouch/agent.sock
    IdentityFile ~/.ssh/yubikey-piv.pub
    IdentitiesOnly yes
    ForwardAgent no
    ControlMaster auto
    ControlPersist 10m
    ControlPath ~/.ssh/yubitouch-%C.sock
```

运行 `ssh internal-target` 时，OpenSSH 会从本机分别认证跳板和目标，不需要 Agent
Forwarding。YubiTouch 有意不支持把 Agent 转发到远程主机，请保持 `ForwardAgent no`。

#### 使用 YubiKey 签署 GitHub Commit

GitHub 的 SSH 登录认证和 Commit 签名是两种独立用途。打开
[SSH and GPG keys](https://github.com/settings/keys)，把 `~/.ssh/yubikey-piv.pub` 的完整
内容添加为 `Signing Key`。如果同一把 key 已经用于 GitHub SSH 登录，仍需再添加一次并将
类型选择为 `Signing Key`。Commit 使用的邮箱也必须是 GitHub 账户中已验证的邮箱。

Git 的 `gpg.ssh.program` 需要调用标准 `ssh-keygen`，而签名进程还必须连接 YubiTouch
Agent socket。为了不替换终端、IDE 或其他程序的默认 `SSH_AUTH_SOCK`，先创建一个只供
Git 签名使用的本地 wrapper。`yubitouch-ssh-sign` 不是项目自带命令；下面的命令会生成它，
并在生成时记录当前 Mac 上 Homebrew OpenSSH 的稳定路径：

```sh
ssh_keygen="$(brew --prefix openssh)/bin/ssh-keygen"
mkdir -p "$HOME/.local/bin"

cat > "$HOME/.local/bin/yubitouch-ssh-sign" <<EOF
#!/bin/sh
export SSH_AUTH_SOCK="\$HOME/.ssh/yubitouch/agent.sock"
exec "$ssh_keygen" "\$@"
EOF

chmod 700 "$HOME/.local/bin/yubitouch-ssh-sign"
```

然后配置当前用户的 Git。`user.signingkey` 使用公钥文件路径；私钥仍留在 YubiKey 中：

```sh
git config --global user.signingkey "$HOME/.ssh/yubikey-piv.pub"
git config --global gpg.format ssh
git config --global gpg.ssh.program "$HOME/.local/bin/yubitouch-ssh-sign"
git config --global commit.gpgsign true
git config --global tag.gpgSign true
```

如果原配置使用 1Password 的 `op-ssh-sign`，第三条命令会只把 Git Commit/Tag 的签名程序
切换到 YubiTouch wrapper，不会改变 SSH Host 的 `IdentityAgent` 配置。检查最终配置：

```sh
git config --global --get-regexp \
  '^(user.signingkey|gpg.format|gpg.ssh.program|commit.gpgsign|tag.gpgsign)$'
```

之后正常运行 `git commit` 或 `git tag -s` 即可。首次加载 provider 时会请求 PIN 或
1Password 授权，每次实际签名都会显示 YubiKey 触摸提醒。推送到 GitHub 后，正确关联的
签名会显示 `Verified`。

### 6. 日常维护、更新和卸载

常用命令：

```text
yubitouch status          查看脱敏状态
yubitouch doctor          检查依赖、权限、设备和 SSH 配置
yubitouch test-sign       独立测试 PIN、触摸和签名链路
yubitouch reload          重启服务并读取配置
yubitouch stop            停止当前用户的 LaunchAgent
```

从源码更新：

```sh
cd /path/to/yubitouch
git pull --ff-only
make test
make vet
make app

# 必须先停止仍在运行的旧 daemon，再覆盖磁盘上的 App。
yubitouch stop
ditto dist/YubiTouch.app /Applications/YubiTouch.app

# 这两行应显示相同的 commit；相同 commit 重建时哈希不会改变。
git rev-parse --short=12 HEAD
yubitouch version

# ensure 从刚复制的 App 启动新的 LaunchAgent daemon。
yubitouch ensure
yubitouch doctor
```

不要只运行 `make app`、`ditto` 和 `yubitouch version`：`version` 会启动一个短暂的 CLI
进程读取新二进制，但原有 daemon 仍可能继续运行旧代码。上述 `stop -> ditto -> ensure`
顺序会明确替换后台进程；更新非敏感配置但没有替换 App 时，使用 `yubitouch reload` 即可。

卸载应用和登录服务：

```sh
yubitouch stop
rm -f "$HOME/Library/LaunchAgents/com.github.mofelee.yubitouch.plist"
rm -f "$HOME/.local/bin/yubitouch"
rm -rf /Applications/YubiTouch.app
```

最后从 `~/.ssh/config` 删除对应 Host 配置。确认不再需要配置和诊断日志后，可以自行删除
`~/.ssh/yubitouch`。PIV 私钥始终留在 YubiKey 中，不会随应用卸载而删除。

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

每次真实签名的浮层会显示发起程序，例如 Terminal、iTerm2、DebianForm、IDE 或
YubiTouch 自己的 `test-sign`，并保留直接 Agent 客户端（通常为 `ssh`）。macOS daemon 在
接受 Unix socket 连接时通过内核 `LOCAL_PEERPID` 捕获直接客户端，再以固定深度追溯父进程；
进程启动时间在路径解析前后必须一致，避免退出进程或 PID 复用把身份串到另一请求。

应用名称优先取自可执行文件所属且代码签名有效的 app bundle；无 bundle、未签名或解析失败
时稳定降级为可执行文件名或“未知程序”，身份解析失败不会阻断签名。程序身份只作为触摸前
的辅助判断，不是对已经控制当前用户会话的恶意软件的身份认证。

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

`make app` 只生成当前 Mac 原生架构的本地应用。项目不分发该产物，也不把它标记为已签名、
已公证或 universal。其他用户应在自己的目标 Mac 上从源码运行测试并构建。

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
chmod 600 ~/.ssh/yubikey-piv.pub
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

1Password Go SDK v0.4.0 的 macOS Desktop App Integration backend 不响应调用方的
`context.Context` 取消（上游 [#266](https://github.com/1Password/onepassword-sdk-go/issues/266)）。
YubiTouch 超时时会终止自己的 `ssh-add` 和一次性 AskPass helper 并返回退出码 6，但
1Password 应用拥有的授权窗口可能继续显示，需要用户在 1Password 中手动取消。YubiTouch
不会通过辅助功能或 UI 自动化操作 1Password 窗口；升级 SDK 前必须重新验证该上游限制。

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
签名结果、请求程序、程序路径、远程主机和完整 1Password secret reference 均不会写入日志。
`yubitouch status`
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

### [DebianForm](https://github.com/mofelee/debianform)

[DebianForm](https://github.com/mofelee/debianform) 是一个通过 OpenSSH 管理 Debian/Ubuntu
主机的声明式配置管理 CLI，不是 SSH 客户端 GUI。它无需 YubiTouch wrapper 或专用集成。
让它继续使用系统 SSH 配置，并让目标 Host 匹配上面的 `IdentityAgent`、`IdentityFile` 和
`IdentitiesOnly` 即可。DebianForm 发起新的 SSH 签名时会出现触摸提示；复用已有连接而没有
新签名时不显示提示是预期行为。

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
| 1Password 授权超时后窗口仍显示 | YubiTouch 已终止自己的 helper；在 1Password 中手动取消该窗口。当前 SDK 上游 #266 不响应 context 取消。 |
| 签名超时 | 保持设备连接，在提示出现后触摸；YubiTouch 不会自动重试该请求。 |
| 重建后版本哈希或界面看起来未更新 | 哈希是 Git commit，不是构建序号。用 `git rev-parse --short=12 HEAD` 核对，然后按 `yubitouch stop`、`ditto`、`yubitouch ensure` 的顺序替换运行中的 daemon。 |
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
- 请求程序身份来自 Unix socket 内核对端信息，不接受 Agent 请求自报的程序名，也不读取 argv。
- 请求程序名称、bundle identifier 和程序路径不会写入状态文件、诊断日志或命令输出。
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

真实签名、设备拔插、Touch ID、OpenSSH/YKCS11 版本矩阵、DebianForm 和全屏 Space 已完成
验收。错误 PIN 测试只应在确认剩余尝试次数的测试设备上执行；1Password 授权窗口取消能力
继续由上游 SDK 问题跟踪，不阻止源码构建使用。
