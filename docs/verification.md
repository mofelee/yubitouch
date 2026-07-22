# YubiTouch v0.1 验证矩阵

本文档用于记录自动化无法覆盖的真实 macOS、YubiKey、1Password、LaunchAgent 和 SSH
客户端结果。每次发布候选版本使用新的矩阵副本或 Issue 评论，保留命令、版本和脱敏结论。
不得记录 PIN、PIN 长度、签名请求/结果、完整 YubiKey 序列号、账户名、完整 secret reference、
恢复 identity、age file key 或 X25519 shared secret。组合 recipient 和插件 identity 只验证格式、
稳定性和绑定结果，不把完整值粘贴到 Issue 或日志。

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
go list -m github.com/1password/onepassword-sdk-go
age --version
go list -m filippo.io/age
command -v age-plugin-yubitouch
```

| 日期 | macOS/build | 架构 | YubiTouch commit | OpenSSH | yubico-piv-tool | ykman | 1Password/SDK | 结果 |
|---|---|---|---|---|---|---|---|---|
| 2026-07-19 | macOS 27.0 (26A5378n) | arm64 | db436e2 | Apple 10.3p1; Homebrew 10.4p1 | 2.7.3 | 5.9.2 | SDK v0.4.0 | pass (#20) |

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
| 触摸浮层主动取消 | pending | pending | 6 | immediate close | 0 |  |
| 错误 PIN | pending | pending | 4 | pending | 0 |  |
| 触摸超时 | pending | pending | 6 | pending | 0 |  |
| 设备移除/重插 | pending | pending | 3 | pending | 0 |  |

1Password 模式另验证：桌面应用集成启用/禁用、Touch ID、用户取消、超时、错误账户和错误
reference。确认未安装 `op` CLI 时仍可工作，失败时不会回退到 prompt。

超时验收区分进程清理与外部 UI：YubiTouch 必须按时返回、终止自己的 `ssh-add`/AskPass
进程且不进入 YubiKey Touch；1Password Go SDK v0.4.0 的 macOS backend 当前不响应 context
取消（上游 #266），因此 1Password 自己拥有的授权窗口可能需要用户手动取消。记录该现象，
但不得用 UI 自动化代替 SDK 取消能力。

## age 插件（#21）

本节把“硬件能力前置 spike”“当前实现的自动化测试”和“发布候选的真实端到端验证”分开
记录。只有真实执行的项目才能写为 `pass`；单元测试通过不能替代 YubiKey 触摸、1Password
授权、进程退出或目标架构验证。

协议、IPC、helper 和 fallback 状态机的自动化基线单独运行：

```sh
go test ./internal/ageprofile ./internal/ageipc ./internal/agehardware \
  ./internal/ageprobe ./internal/agehelper ./internal/ageservice ./internal/command
```

这些测试应覆盖 age v1.3.1 插件回合和固定向量，并拒绝未知版本/算法/路径、非规范或低阶
X25519 key、错误 hardware ID/binding、重复 hardware/recovery、缺失 hardware、recovery 复用
hardware ID 和损坏 ciphertext。另验证 connected 可解启用/禁用/轮换 recovery 前的密文，而
missing fallback 只接受与当前配置 recovery ID 完全匹配的 stanza。

私钥 helper 的自动化验证还应确认：macOS+cgo 下只有启用 Hardened Runtime 的同一可执行文件
直接派生的 helper 能通过父进程认证；普通 `go test`/`go build`、`DYLD_INSERT_LIBRARIES`
注入、经 shell 或不同可执行文件直接启动时只返回固定失败分类。注入负例必须实际加载一个带
constructor 的测试 dylib，并确认 constructor 不执行。在拒绝路径中，配置读取、PIN provider、
1Password identity 解析和 PKCS#11 派生都必须保持零调用；不支持这项认证的平台或未启用 cgo
的构建必须失败关闭。另以真实 launcher 子进程启动一个阻塞 helper 和孙进程，`SIGKILL`
launcher 后确认两者都在短时限内消失。

### 当前已验证的硬件前置条件

| 日期 | macOS/build | 架构 | YubiKey firmware | YKCS11 | age | 范围 | 结果 |
|---|---|---|---|---|---|---|---|
| 2026-07-22 | macOS 27.0 (26A5388g) | arm64 | 5.7.4 | 2.7.3 | v1.3.1 | PIV 82 X25519/YKCS11 ECDH spike | pass |
| 2026-07-22 | macOS 27.0 (26A5388g) | arm64 | 5.7.4 | 2.7.3 | v1.3.1 | 签名 App：公开描述符、离线加密、硬件解密及 1Password PIN/触摸时序 | pass（连续 2 次解密） |

arm64 spike 使用用户预先配置的 PIV 82 X25519 key，策略为 PIN `ONCE`、touch `ALWAYS`。
已确认无 PIN/login 可读取规范的 32 字节公钥，登录并触摸后
`CKM_ECDH1_DERIVE` 成功，结果与 Go `crypto/ecdh` X25519 通过常量时间比较一致。
验证过程没有生成、导入、覆盖、删除或修改任何硬件 key，也没有记录完整设备 serial、PIN、
ECDH 输入、shared secret 或 file key。

第一条 spike 只解除 arm64 硬件能力的前置阻断；第二条记录完成了源码签名 App 的公开
recipient/identity、无 daemon/设备的离线加密，以及硬件主路径端到端解密。它不代表任何
真实 1Password recovery 路径已通过。

### 安装、格式与离线加密

先确认 App bundle 和 `PATH` 中都有精确命名的插件；主 `yubitouch` 可执行文件不能改名代替：

```sh
test -x /Applications/YubiTouch.app/Contents/MacOS/age-plugin-yubitouch
test "$(command -v age-plugin-yubitouch)" = "$HOME/.local/bin/age-plugin-yubitouch"
test "$(readlink "$HOME/.local/bin/age-plugin-yubitouch")" = \
  /Applications/YubiTouch.app/Contents/MacOS/age-plugin-yubitouch
```

在本地按 README 配置六个 `YUBITOUCH_AGE_*` 输入。完整 serial、1Password reference 和
恢复 identity 只留在本机，不放入测试记录。确认以下三个私钥环境变量中的任意一个非空都会
使 `configure` 失败：`YUBITOUCH_AGE_RECOVERY_IDENTITY`、
`YUBITOUCH_AGE_RECOVERY_PRIVATE_KEY`、`YUBITOUCH_AGE_RECOVERY_SECRET`。

用私有临时目录检查输出恰好一行、格式正确且重复生成稳定；不要打开或打印这些文件：

```sh
age_verify_dir="$(mktemp -d)"
chmod 700 "$age_verify_dir"
yubitouch age recipient > "$age_verify_dir/recipient.txt"
yubitouch age identity > "$age_verify_dir/identity.txt"
chmod 600 "$age_verify_dir/identity.txt"

test "$(wc -l < "$age_verify_dir/recipient.txt")" -eq 1
test "$(wc -l < "$age_verify_dir/identity.txt")" -eq 1
awk 'NR == 1 && /^age1yubitouch1[0-9a-z]+$/ { ok = 1 } END { exit !(ok && NR == 1) }' \
  "$age_verify_dir/recipient.txt"
awk 'NR == 1 && /^AGE-PLUGIN-YUBITOUCH-1[0-9A-Z]+$/ { ok = 1 } END { exit !(ok && NR == 1) }' \
  "$age_verify_dir/identity.txt"

yubitouch age recipient > "$age_verify_dir/recipient-second.txt"
yubitouch age identity > "$age_verify_dir/identity-second.txt"
cmp -s "$age_verify_dir/recipient.txt" "$age_verify_dir/recipient-second.txt"
cmp -s "$age_verify_dir/identity.txt" "$age_verify_dir/identity-second.txt"
```

首次执行从不含 `age.public_key` 缓存的专用测试配置开始，不要手工改动生产配置。插入目标设备，
确认读取公钥不请求 PIN、不显示触摸 UI；
随后拔出设备再次执行，确认命令只使用缓存且输出仍稳定。配置了 recovery 时，生成 recipient
不得触发 1Password 授权或读取恢复 identity。自动化还要证明只读 public/probe helper 的目标
只出现在有界 pipe，不进入 argv、继承环境或 stderr；挂起 child 及其孙进程在 timeout/cancel
后被整组终止并 `wait`，父 launcher 被 `SIGKILL` 后也必须在短时限内一并消失；crash、超大/
尾随/合法响应后非零退出均折叠为预定义分类，随后请求仍可成功。

用可控 reader 暂停首次硬件公钥读取，并在窗口内并发运行 `configure`：只修改 recovery/日志等
非目标字段时，最终输出必须使用新 recovery 且磁盘配置保留全部并发修改；修改 serial、slot 或
algorithm 时，本次命令必须无 stdout、不得缓存旧公钥，并返回固定的“配置已变化”错误。

验证离线加密时先保存 recipient，再停止 daemon 并拔出设备。只使用无敏感内容的测试文件：

```sh
printf 'YubiTouch age verification\n' > "$age_verify_dir/plaintext"
yubitouch stop
age -R "$age_verify_dir/recipient.txt" \
  -o "$age_verify_dir/plaintext.age" "$age_verify_dir/plaintext"
test -s "$age_verify_dir/plaintext.age"
```

这一步必须在没有 daemon、YubiKey 和 1Password 访问的情况下成功。完成后运行
`yubitouch ensure` 恢复服务；整个验证期间禁止设置 `AGEDEBUG=plugin`，因为 age 上游调试
输出可能包含插件协议内容和 file key。

### 硬件主路径

插入配置的目标 YubiKey 并运行：

```sh
yubitouch ensure
age -d -i "$age_verify_dir/identity.txt" \
  -o "$age_verify_dir/decrypted" "$age_verify_dir/plaintext.age"
cmp -s "$age_verify_dir/plaintext" "$age_verify_dir/decrypted"
```

确认请求先完成配置的 PIN provider，再显示“age 解密”原生触摸提示，最后只执行 hardware
stanza，且没有 1Password recovery 授权。使用 1Password 作为 PIN provider 时，在 Desktop
App 授权仍阻塞期间不得出现 YubiTouch 触摸面板；PIN provider 失败、取消或 YKCS11 login
拒绝 PIN 也不得短暂显示该面板。`status --json` 只采集以下脱敏字段：

```sh
yubitouch status --json | jq '{
  age_configured,
  age_socket_reachable,
  age_recovery_configured,
  age_backend,
  age_result,
  last_age_at
}'
```

| 场景 | 预期 backend | recovery 调用 | 预期结果 | arm64 |
|---|---|---:|---|---|
| 目标设备连接且解密成功 | hardware | 0 | success | pass（连续 2 次；PIN 授权结束后才显示触摸） |
| 插入其他 YubiKey | none | 0 | target mismatch | pending |
| serial/slot/public key 不匹配 | none | 0 | target mismatch | pending |
| 探测失败或状态不明 | none | 0 | probe unavailable | pending |
| PIN provider 失败/取消 | hardware | 0 | fail closed | pending |
| 触摸取消 | hardware | 0 | canceled | pending |
| 触摸超时 | hardware | 0 | timeout | pending |
| 设备在操作中移除 | hardware | 0 | fail closed | pending |
| YKCS11/ECDH/KDF/AEAD 失败 | hardware | 0 | fail closed | pending |

2026-07-22 的 arm64 隔离验收使用 1Password PIN provider。两次请求都在 Desktop App 授权
窗口保持未完成时等待，期间没有出现 YubiTouch 触摸面板；授权完成后才显示“age 解密”触摸
提示。两次触摸后 `age` 均以 0 退出，解密结果均与原文匹配，脱敏状态依次记录
`age_hardware_selected` 和 `age_decrypt_succeeded`。本次配置未启用 recovery，因此不改变下方
真实 recovery 矩阵的 `pending` 状态。

错误 PIN 会消耗 YubiKey 的有限重试次数。只允许在已确认剩余次数、拥有可靠恢复方案且专门
用于测试的设备上验证；不得为了补齐矩阵而对日常使用设备尝试错误 PIN，并确认实现不会自动
重试。任何已经选择 hardware 的请求都不得在同一次请求中改走 recovery。

另以一个等待中的 SSH 签名和一个 age 解密互换先后顺序，确认两者共享全局 PIV 队列且一次
只有一个进入 PIN/触摸/私钥操作。取消仍在排队的请求时，不得启动其 PIN、UI 或 PIV 操作；
客户端断开和触摸 UI 取消只影响对应 request ID，下一条请求仍可成功。

### 严格 recovery

仅在本机 1Password 中配置并引用独立的原生 age X25519 identity；不要把 identity 或完整
reference 放入命令、Issue 或测试附件。先拔出所有 YubiKey，确认针对配置目标的两次有界探测
都成功返回 `not_detected`，中间经过防抖，才执行同一个解密命令。一次请求只能启动一次
recovery helper，不能先尝试 hardware ECDH，也不能改变 SSH `agent_route`。

| 真实 recovery 场景 | helper 退出/回收 | 自动重试 | 明文/失败 | 当前结果 |
|---|---|---:|---|---|
| 成功授权且 identity 匹配 | 必须 | 0 | 明文匹配 | pending |
| 用户拒绝/取消 1Password 授权 | 必须 | 0 | 失败 | pending |
| helper/SDK 超时或客户端取消 | 必须 | 0 | 失败 | pending |
| helper 崩溃/异常退出 | 必须 | 0 | 失败 | pending |
| identity 与配置 recipient 不匹配 | 必须 | 0 | 失败 | pending |

截至 2026-07-22，上表全部是真实环境待验证项，不得依据 mock、单元测试或 arm64 硬件 spike
改为 `pass`。验收时确认没有孤儿 helper、临时 secret 文件或持久化 identity；1Password SDK
返回的不可变 Go `string` 无法可靠清零，必须把禁用 core dump、短 helper 生命周期和进程退出
作为主要隔离边界，不能宣称达到硬件私钥不可导出的安全级别。

启用 recovery 还意味着 hardware 与 recovery 是 OR 关系，任一私钥都能独立恢复 file key；
验证报告必须明确这会把整份密文的整体安全级别降低到较弱路径。完成测试后删除临时目录，
并只记录矩阵结果、版本和 Issue 链接，不保留 identity、reference、file key 或 shared secret。

## 1Password 缺卡直接路由（#20）

本节是真机验收清单，初始结果一律为 `pending`。不得因为单元测试通过就把真实
YubiKey、1Password Touch ID、OpenSSH 或远程转发场景记为通过。开始前按 README 完成
`agent.toml` 身份隔离，确认 1Password SSH Agent 只暴露与 PIV 9A 指纹相同的一把 key。

所有测试 Host 都必须先检查 OpenSSH 最终配置：

```sh
ssh -G example-yubikey 2>/dev/null |
  awk '$1 ~ /^(proxyjump|identityagent|identityfile|identitiesonly|forwardagent|controlmaster|controlpath|controlpersist)$/ {print}'
```

`identityagent` 必须是稳定的 `~/.ssh/yubitouch/agent.sock`，`identityfile` 必须是
配置的 PIV 公钥，`identitiesonly` 必须为 `yes`。实际主机名、用户名和公钥内容
不得粘贴到 Issue；只记录指纹是否一致。

使用这个脱敏视图观察路由：

```sh
yubitouch status --json | jq '{
  agent_reachable,
  piv_agent_socket,
  piv_agent_reachable,
  agent_route,
  route_probe_state,
  route_changed_at,
  route_state_stale,
  route_guard_ready,
  fallback_enabled,
  fallback_agent,
  fallback_checked,
  fallback_agent_reachable,
  fallback_key_available,
  fallback_other_keys,
  yubikey_state
}'
```

### 安装迁移与失败闭合

1. 按 README 的 `stop -> ditto -> configure -> ensure` 顺序从旧版替换应用，启用回退时运行
   `YUBITOUCH_FALLBACK_AGENT=1password yubitouch configure`。
2. 确认 `test -L "$HOME/.ssh/yubitouch/agent.sock"` 成功；YubiKey 存在时，`readlink`
   结果应指向 `piv-agent.sock`，不是 backend socket。
3. 运行 `yubitouch doctor`，确认公共路由、PIV socket、1Password socket、目标 key、
   零个其他 key、`IdentityFile` 和 `IdentitiesOnly` 全部通过。
4. 在稳定缺卡且 `agent_route=1password` 时分别执行 `yubitouch reload` 和
   `yubitouch stop`。`reload` 恢复后只能在再次完成缺卡防抖及回退检查后
   返回 1Password；`stop` 后公共链接不得仍指向 1Password。最后运行 `yubitouch ensure`
   恢复服务。

### 拔出、去抖与重插

1. 插入 YubiKey，运行 `yubitouch reload`，确认 `agent_route=piv`、
   `route_probe_state=connected` 且公共链接指向 `piv-agent.sock`。
2. 拔出 YubiKey，高频率观察上面的脱敏状态。IOKit 明确报告 `not_detected` 后必须先进入
   `piv_fail_closed`，公共链接仍指向 PIV；只有防抖时间结束后仍缺卡才能进入
   `agent_route=1password`。
3. 另做一次短暂拔插：在首次 `not_detected` 后、防抖时间结束前重插。此次不得
   出现 `agent_route=1password`，恢复后应直接返回 `piv`。
4. 在稳定缺卡路由上运行 `yubitouch test-sign`。确认出现 1Password Touch ID/授权、
   签名成功、没有 YubiTouch 触摸浮层，且 `last_sign_at` 不因这次直接签名更新。
5. 重新插入 YubiKey。下一次成功探测应返回 `piv`；再运行一次 `test-sign`，
   确认走 PIV PIN/触摸链路并更新 `last_sign_at`。
6. 在 `piv` 路由上执行一次真实 session-bind 回合：

   ```sh
   YUBITOUCH_LIVE_AGENT_SOCKET="$HOME/.ssh/yubitouch/agent.sock" \
     go test ./internal/agentproxy \
       -run '^TestLiveAgentSessionBindRoundTrip$' -count=1 -v
   ```

   测试必须实际执行而不是 skip，以验证 PIV Agent 没有吞掉
   `session-bind@openssh.com`。缺卡路由不经过 YubiTouch Agent；1Password Agent 当前会对
   直接发送的裸 `session-bind@openssh.com` 返回 `SSH_AGENT_EXTENSION_FAILURE`。因此缺卡
   验收应比较公开 socket 与 1Password 原始 socket 的响应完全一致，并以真实 OpenSSH
   新连接成功为准，不能要求这个 PIV 专用回合测试成功。公开 socket 不得代理、吞掉或改写
   1Password 的扩展响应。

### ControlMaster 与 ProxyJump

1. 缺卡并等待 `agent_route=1password`，关闭测试 Host 的旧 master，再建立一条新连接：

   ```sh
   ssh -O exit example-yubikey 2>/dev/null || true
   ssh example-yubikey 'printf "YUBITOUCH_FALLBACK_OK\n"'
   ssh -O check example-yubikey
   ```

   首次认证应由 1Password 完成。再次运行普通 `ssh example-yubikey true`，确认
   ControlMaster 复用不显示任何 UI。
2. 保留该 master 并重插 YubiKey，等待公共路由回到 PIV。已有 master 仍应可复用；
   运行 `ssh -O exit example-yubikey` 后的新连接才应走 PIV 触摸链路。
3. 配置 `internal-target` 通过 `bastion` 的 ProxyJump，两台主机都只接受目标公钥。
   在缺卡路由上关闭两者 master 后运行：

   ```sh
   ssh internal-target 'printf "YUBITOUCH_PROXYJUMP_FALLBACK_OK\n"'
   ssh -O check bastion
   ssh -O check internal-target
   ssh internal-target 'printf "YUBITOUCH_PROXYJUMP_REUSE_OK\n"'
   ```

   首次建立应由 1Password 完成所需签名，复用时不应有 UI。ProxyJump 本身不需要
   `ForwardAgent yes`。

### Agent Forwarding 边界

只在专用且完全可信的测试主机上运行本节。远程主机可以利用转发 Agent 请求签名，
因此不能用生产跳板代替测试主机。

1. 用 `ForwardAgent no` 的新连接确认远程没有本地转发 socket。强制禁用 ControlMaster，
   避免测试实际复用一条旧 transport：

   ```sh
   ssh \
     -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
     -o ForwardAgent=no \
     trusted-test-host 'test -z "${SSH_AUTH_SOCK:-}"'
   ```

2. 在 `agent_route=1password` 时，仅对该测试 Host 用 `-A` 建立一次性连接，在远程运行
   `ssh-add -l`。只记录身份数量和指纹，确认恰好一把且是目标 key；不要粘贴公钥全文：

   ```sh
   ssh -A \
     -o ControlMaster=no -o ControlPath=none -o ControlPersist=no \
     trusted-test-host 'test -S "$SSH_AUTH_SOCK" && ssh-add -l'
   ```

3. 如果要验证真实转发签名，只从该可信主机连接专用测试目标。确认本机由
   1Password 显示授权，不显示 YubiTouch 触摸浮层。
4. 结束后立即关闭 ControlMaster。路由切换不会把已打开的 Agent 连接迁移到另一 Agent，
   因此不能把“重插后状态显示 PIV”当作旧转发连接已失效的证据。

### Git Commit 签名

使用 README 中原有的 `yubitouch-ssh-sign` wrapper，不修改 `gpg.ssh.program`。在临时 repo 中
分别于 `agent_route=1password` 和 `agent_route=piv` 执行一次 `git commit -S`：

```sh
tmp_repo="$(mktemp -d)"
git -C "$tmp_repo" init -q
git -C "$tmp_repo" config user.name 'YubiTouch Verification'
git -C "$tmp_repo" config user.email 'verification@example.invalid'
git -C "$tmp_repo" config user.signingkey "$HOME/.ssh/yubikey-piv.pub"
git -C "$tmp_repo" config gpg.format ssh
git -C "$tmp_repo" config gpg.ssh.program "$HOME/.local/bin/yubitouch-ssh-sign"
awk 'NF >= 2 { print "verification@example.invalid", $1, $2 }' \
  "$HOME/.ssh/yubikey-piv.pub" > "$tmp_repo/allowed_signers"
git -C "$tmp_repo" config gpg.ssh.allowedSignersFile "$tmp_repo/allowed_signers"

# 缺卡并确认 agent_route=1password 后执行：
git -C "$tmp_repo" commit --allow-empty -S -m 'fallback route'

# 重插并确认 agent_route=piv 后执行：
git -C "$tmp_repo" commit --allow-empty -S -m 'piv route'

git -C "$tmp_repo" verify-commit HEAD~1
git -C "$tmp_repo" verify-commit HEAD
rm -rf -- "$tmp_repo"
```

缺卡 commit 应只出现 1Password Touch ID/授权，PIV commit 应出现 YubiTouch 触摸链路。
两个 commit 都必须通过 SSH 签名密码学验证，证明同一 wrapper 可以跨路由使用。

| 候选 commit | 安装/重载失败闭合 | 拔插/去抖 | session-bind | ControlMaster | ProxyJump | ForwardAgent 边界 | Git 签名 | 结果/Issue |
|---|---|---|---|---|---|---|---|---|
| db436e2 | pass | pass | pass | pass | pass | pass | pass | pass (#20) |

## LaunchAgent 与无副作用查询

1. 运行 `yubitouch ensure`，确认 plist 位于
   `~/Library/LaunchAgents/com.github.mofelee.yubitouch.plist`。
2. 运行 `launchctl print gui/$UID/com.github.mofelee.yubitouch`，记录 daemon PID。
3. 插入 YubiKey，确认 `agent_route=piv`，在 provider 尚未加载时运行：

   ```sh
   SSH_AUTH_SOCK="$HOME/.ssh/yubitouch/agent.sock" ssh-add -L
   yubitouch status --json
   ```

   确认只列出配置公钥，且没有 PIN、Touch ID、UI 或 backend provider 加载。
4. 启用 1Password 回退并保持 daemon 运行至少 10 秒，然后执行测试设备上已知安全的
   `ykman piv` 读取或管理操作。确认操作不会出现 `SCARD_W_UNPOWERED_CARD`、
   `Card is unpowered` 或伪装成 `PIN verification failed` 的连接错误；不要在验证记录中写入 PIN
   或设备序列号。
5. 对记录的 daemon PID 发送 `SIGKILL`，确认 launchd 拉起新 PID、公共受管路由恢复，随后重复
   identity 查询并确认仍无 provider 副作用。只操作该次 `launchctl print` 确认的 daemon PID。
6. 分别运行 `yubitouch reload`、`yubitouch stop` 和 `yubitouch ensure`，确认 socket/进程状态
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

显式 `session-bind@openssh.com` 的 PIV 实机验证使用本地公共 Agent 路由，不开启 Agent Forwarding，
也不连接远程主机：

```sh
YUBITOUCH_LIVE_AGENT_SOCKET="$HOME/.ssh/yubitouch/agent.sock" \
  go test ./internal/agentproxy -run '^TestLiveAgentSessionBindRoundTrip$' -count=1 -v
```

测试在内存中生成临时 host key、session ID 和有效 host signature，先发送 session-bind，再通过
同一客户端连接执行目标 key 签名并验证结果。这样覆盖 PIV Agent 的缓存、真实 OpenSSH backend
重放和 YubiKey 签名链路，不把 Agent 暴露给远端。

## UI 与安全检查

在 PIV 路由上，于普通桌面、多 Space 和全屏应用中检查等待、成功、失败和超时状态。确认提示不抢焦点，
成功由签名结果关闭，设备移除显示失败，多个并发请求不会叠加窗口。点击取消按钮后浮层
立即关闭、调用方失败且没有成功状态；随后排队请求使用自己的按钮/request ID，不能被旧点击取消。
回退路由的 Touch ID/授权界面完全由 1Password 验收，不应出现 YubiTouch 触摸浮层。

人工检查 `ps`、进程环境、`config.json`、`state.json`、诊断日志和运行目录中的文件名/内容。
只确认敏感字段不存在，不要把真实 PIN 作为 shell 搜索参数或保存检查输出。报告中只记录
“通过/失败 + Issue 链接”；发现泄漏时先停止测试并按敏感信息处理流程清理证据。
