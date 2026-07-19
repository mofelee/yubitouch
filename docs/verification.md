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

## 1Password 缺卡直接路由（#20）

本节是真机验收清单，初始结果一律为 `pending`。不得因为单元测试通过就把真实
YubiKey、1Password Touch ID、OpenSSH 或远程转发场景记为通过。开始前按 README 完成
`agent.toml` 身份隔离，确认 1Password SSH Agent 只暴露与 PIV 9A 指纹相同的一把 key。

所有测试 Host 都必须先检查 OpenSSH 最终配置：

```sh
ssh -G example-yubikey 2>/dev/null |
  awk '$1 ~ /^(identityagent|identityfile|identitiesonly|forwardagent|controlmaster|controlpath|controlpersist)$/ {print}'
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
   `yubitouch stop`。`reload` 恢复后只能在再次完成两次缺卡探测及回退检查后
   返回 1Password；`stop` 后公共链接不得仍指向 1Password。最后运行 `yubitouch ensure`
   恢复服务。

### 拔出、去抖与重插

1. 插入 YubiKey，运行 `yubitouch reload`，确认 `agent_route=piv`、
   `route_probe_state=connected` 且公共链接指向 `piv-agent.sock`。
2. 拔出 YubiKey，高频率观察上面的脱敏状态。第一次明确 `not_detected` 必须先进入
   `piv_fail_closed`，公共链接仍指向 PIV；只有第二次连续缺卡才能进入
   `agent_route=1password`。
3. 另做一次短暂拔插：在第一次 `not_detected` 后、第二次探测前重插。此次不得
   出现 `agent_route=1password`，恢复后应直接返回 `piv`。
4. 在稳定缺卡路由上运行 `yubitouch test-sign`。确认出现 1Password Touch ID/授权、
   签名成功、没有 YubiTouch 触摸浮层，且 `last_sign_at` 不因这次直接签名更新。
5. 重新插入 YubiKey。下一次成功探测应返回 `piv`；再运行一次 `test-sign`，
   确认走 PIV PIN/触摸链路并更新 `last_sign_at`。
6. 在 `piv` 和 `1password` 两种路由上分别执行一次真实 session-bind 回合：

   ```sh
   YUBITOUCH_LIVE_AGENT_SOCKET="$HOME/.ssh/yubitouch/agent.sock" \
     go test ./internal/agentproxy \
       -run '^TestLiveAgentSessionBindRoundTrip$' -count=1 -v
   ```

   两次都必须实际执行而不是 skip，以验证稳定入口没有吞掉
   `session-bind@openssh.com`。

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

1. 用 `ForwardAgent no` 的新连接确认远程没有本地转发 socket。
2. 在 `agent_route=1password` 时，仅对该测试 Host 用 `-A` 建立新连接，在远程运行
   `ssh-add -L`。只记录身份数量和指纹，确认恰好一把且是目标 key；不要粘贴公钥全文。
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

# 缺卡并确认 agent_route=1password 后执行：
git -C "$tmp_repo" commit --allow-empty -S -m 'fallback route'

# 重插并确认 agent_route=piv 后执行：
git -C "$tmp_repo" commit --allow-empty -S -m 'piv route'

for rev in HEAD~1 HEAD; do
  git -C "$tmp_repo" cat-file commit "$rev" | grep -q '^gpgsig '
done
rm -rf "$tmp_repo"
```

缺卡 commit 应只出现 1Password Touch ID/授权，PIV commit 应出现 YubiTouch 触摸链路。
两个 commit 都必须含有 SSH `gpgsig`，证明同一 wrapper 可以跨路由使用。

| 候选 commit | 安装/重载失败闭合 | 拔插/去抖 | session-bind | ControlMaster | ProxyJump | ForwardAgent 边界 | Git 签名 | 结果/Issue |
|---|---|---|---|---|---|---|---|---|
|  | pending | pending | pending | pending | pending | pending | pending | #20 |

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
4. 对记录的 daemon PID 发送 `SIGKILL`，确认 launchd 拉起新 PID、公共受管路由恢复，随后重复
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
