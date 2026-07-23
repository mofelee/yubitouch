# YubiTouch age 功能参考

本文档说明 `age-plugin-yubitouch` 的功能、配置、路径选择、进程边界、协议和已知限制。实际
配置与加解密步骤见 [使用教程](age-tutorial.md)，真实环境结果见
[验证矩阵](verification.md#age-插件21)。

## 功能范围

YubiTouch 为 age 提供一个默认 profile：

- 一把已经存在于明确 YubiKey PIV serial 和 slot 中的 X25519 硬件主密钥；
- 最多一把可选的、与硬件 key 独立的原生 age X25519 recovery key；
- recovery 私钥通过 1Password Desktop App Integration 按需读取；
- 加密生成 hardware wrap，并在启用 recovery 时生成第二份 recovery wrap；
- 解密优先使用 hardware，只有明确确认目标设备未连接时才允许 recovery。

YubiTouch 不生成、导入、同步、轮换、删除或覆盖 PIV key，也不管理 Management Key、PIN、
PUK 或 PIV 证书。格式与 `age-plugin-yubikey` 完全独立且不兼容。

硬件对象必须实际为 X25519，并严格使用 PIN policy `ONCE` 和 touch policy `ALWAYS`。策略不
匹配时 helper 失败闭合，YubiTouch 不会自动重写该槽位。

当前真实验收覆盖 macOS arm64、YubiKey PIV X25519、YKCS11 2.7.3、age v1.3.1 和
1Password SDK v0.4.0。私钥 helper 依赖 macOS+cgo 和 Hardened Runtime 身份认证。

YubiTouch 中涉及 1Password 的三种能力彼此独立：

- `pin_provider=1password`：设备连接时为 PIV hardware 操作读取 PIN；
- age recovery：明确缺卡时读取独立的软件 X25519 identity；
- SSH fallback agent：缺卡时切换公共 SSH Agent 路由。

启用其中一个不会隐式启用另外两个，age recovery 也不会改变 SSH route。

## 组件和数据流

```text
加密：

plaintext -> age file key -> encrypted file body
                    |
                    +-> hardware public key -> hardware wrap
                    `-> recovery public key -> recovery wrap（可选）

解密：

age
 `-> age-plugin-yubitouch
      `-> ~/.ssh/yubitouch/age.sock
           `-> YubiTouch daemon
                +-> one-shot public/probe helper
                +-> persistent hardware helper
                |    +-> one-shot PIN resolver
                |    `-> reusable YKCS11 session / PIV X25519 ECDH
                `-> one-shot recovery helper / 1Password
```

文件正文只使用同一个 16 字节 age file key 加密一次。hardware 和 recovery 分别包装该 file
key，不会生成两份正文。加密只需要 recipient 中的公开材料，不使用 daemon、设备或
1Password；解密统一经过 daemon 的独立私有 socket，不复用 SSH Agent 协议。

## 对外格式

### Recipient

`yubitouch age recipient` 输出单行 `age1yubitouch1...`。v1 payload 包含：

- 版本、`x25519` 算法号、recovery flag 和零保留字节；
- 16 字节 profile ID；
- 16 字节 hardware key ID 和 32 字节规范化 hardware 公钥；
- 启用 recovery 时，再包含独立的 recovery key ID 和 recovery 公钥。

recipient 只包含公开材料，可以交给不运行 YubiTouch 的加密端。

### Identity

`yubitouch age identity` 输出单行 `AGE-PLUGIN-YUBITOUCH-1...`。它只包含版本、算法、profile
ID 和 hardware key ID，不包含公钥、设备 serial、slot、PIN、1Password reference 或私钥。

profile ID 只绑定 hardware 公钥，因此增加、删除或轮换 recovery 不改变 identity。identity
仍依赖本机配置和 daemon，不是可独立解密的私钥文件。

## 配置

配置保存在 `~/.ssh/yubitouch/config.json` 的可选 `age` 段中。配置文件权限固定为 `0600`，
嵌套对象不接受未知字段。

| 配置字段 | configure 环境变量 | 约束 |
|---|---|---|
| `age.serial` | `YUBITOUCH_AGE_SERIAL` | 规范的非零十进制 uint32 |
| `age.slot` | `YUBITOUCH_AGE_SLOT` | `9a`、`9c`、`9d`、`9e` 或 `82` 到 `95` |
| `age.algorithm` | `YUBITOUCH_AGE_ALGORITHM` | 仅 `x25519` |
| `age.recovery.provider` | `YUBITOUCH_AGE_RECOVERY_PROVIDER` | 仅 `1password` |
| `age.recovery.identity_ref` | `YUBITOUCH_AGE_RECOVERY_IDENTITY_REF` | 规范的直接 `op://` secret reference |
| `age.recovery.recipient` | `YUBITOUCH_AGE_RECOVERY_RECIPIENT` | 规范的原生 age X25519 `age1...` recipient |

recovery 复用顶层 `onepassword_account`。如果 hardware PIN provider 也是 1Password，PIN
item 和 recovery item 必须位于同一个配置 account；更新 recovery 时更改该全局字段也会影响
下一次 hardware PIN 解析。当前环境变量只在显式执行 `yubitouch configure` 时按“环境变量 >
已有配置 > 默认值”合并并持久化。daemon 不读取交互式 shell 环境，也不接受每次解密的
serial、slot、algorithm、recovery key 或 reference 覆盖。

以下变量用于直接传递恢复私钥，始终被拒绝：

```text
YUBITOUCH_AGE_RECOVERY_IDENTITY
YUBITOUCH_AGE_RECOVERY_PRIVATE_KEY
YUBITOUCH_AGE_RECOVERY_SECRET
```

`age.public_key` 是首次运行 `yubitouch age recipient|identity` 时从目标槽位只读并缓存的
32 字节公开值，不接受环境变量覆盖。`age.sock` 从实际配置文件目录派生，不写入配置文件。

## 加密行为

recipient 对每条路径生成独立的临时 X25519 key。每个 stanza 形式为：

```text
-> yubitouch v1 hardware|recovery <profile-id> <key-id>
<32-byte ephemeral public key || 32-byte authenticated ciphertext>
```

X25519 shared secret 使用 HKDF-SHA256 派生 wrapping key。domain-separated salt/info、profile
ID、key ID、路径、临时公钥和目标公钥都参与派生或关联数据绑定；16 字节 file key 使用
ChaCha20-Poly1305 认证包装。

解析器拒绝未知版本、算法、路径、flag、非零保留位、错误长度、非规范编码、低阶 X25519
key、错误或复用的 ID、重复/缺失 stanza 和 AEAD 认证失败。插件使用 age 官方 plugin API，
当前协议自动化目标为 age v1.3.1。

## 解密路径选择

每次请求先验证 identity、profile、stanza 和当前配置，再在有界 helper 中探测明确配置的目标。

| 探测或操作结果 | backend | 行为 |
|---|---|---|
| 目标 serial、slot 和公钥匹配 | `hardware` | 只使用 hardware stanza |
| 连续两次探测均明确 `not_detected`，并存在匹配 recovery stanza | `recovery` | 启动一次 recovery helper |
| 缺卡但未配置 recovery 或密文没有 recovery stanza | `none` | `device_not_detected` |
| 插入其他设备或目标不匹配 | `none` | `target_mismatch`，不 recovery |
| 探测超时、异常或状态不明 | `none` | `probe_unavailable`，不 recovery |
| 请求/profile/stanza 与配置不一致 | `none` | `invalid_request` 或 `configuration` |

任何已经选择 hardware 的请求都不会在失败后切换到 recovery。错误 PIN、PIN provider
失败/取消、触摸取消/超时、设备移除、session 失效、YKCS11、ECDH、KDF、AEAD 或协议错误都
只结束当前 hardware 请求。

这种失败闭合规则防止攻击者通过干扰硬件认证或通信，强制 daemon 读取 1Password recovery
identity。

## Hardware 路径

### PIN、login 和触摸顺序

hardware 请求与 SSH PIV 签名共享同一个全局协调器，任何时刻最多只有一个请求进入需要 PIN、
触摸或私钥操作的 PIV 区域。

1. daemon 为未认证 session 启动一次性 PIN resolver；
2. resolver 完成 `prompt` 或 1Password PIN provider，把有界响应交给 hardware helper；
3. hardware helper 等待并回收 resolver 后执行 `C_Login`，随后清零可变 PIN 缓冲区；
4. session/key 验证成功后，daemon 才显示“age 解密”触摸提示，并立即释放 helper 继续；
5. helper 执行 `CKM_ECDH1_DERIVE`，在设备内等待并由用户的物理触摸授权，然后解开
   hardware wrap；
6. helper 只返回 file key，不返回 PIN、私钥或原始 shared secret。

PIN provider 未结束、失败或取消时不会显示触摸提示。

### 已认证 session 复用

正常成功后，daemon 可以保留常驻 hardware helper 中的已认证 YKCS11 session。后续请求不再
运行 PIN resolver，但仍重新校验 token、session、private object 和 key，并为每次 ECDH 执行
独立的 `ready_for_touch -> UI -> continue`。`Touch policy: ALWAYS` 仍是每次操作的授权门。

首版没有额外的时间型空闲或绝对 TTL；实现仍有 65,536 个请求 ID 的有界 replay 上限，到达
上限时会重建 helper。以下任一事件也会销毁并回收 helper/session，下一次请求重新执行 PIN
provider 和 login：

- 任意 YubiKey 插入、移除或替换事件；
- 配置 reload，包括 serial、slot、algorithm 或 public key 变化；
- daemon 停止、崩溃、重启，或 hardware helper 退出；
- token、session、private object、PKCS#11、ECDH、解包或帧协议错误；
- 已经绑定当前 hardware helper 的请求被客户端取消、断开、超时或通过触摸 UI 取消；
- helper 父进程/代码身份验证失败，生命周期管道关闭或设备事件流异常结束。

进入 hardware helper 的请求只有正常成功才保留 session。ECDH 已开始或结果状态不明时不自动
重试。

## Recovery 路径

只有两次有界探测都成功且明确返回 `not_detected`，中间经过短暂去抖，才允许 recovery。每个
请求创建一个全新的 recovery helper，不复用 SDK client、授权或 recovery identity。

helper 执行以下工作：

1. 通过配置的 1Password account 和 direct secret reference 请求一次授权；
2. 读取并严格解析唯一的原生 age X25519 identity；
3. 派生公开 recipient，并与配置值完全比较；
4. 在 helper 内完成 X25519、KDF、AEAD 和 file key 解包；
5. 只返回成功解出的 file key，然后立即退出。

授权拒绝、SDK 不可用或 identity 无法解析通常归类为 `recovery_unavailable`；已得到有效
identity 但 recipient 不匹配、解包失败或 helper 异常则归类为 `recovery_failed`。任何结果都
不自动重试另一个 item、key 或 hardware stanza。

age recovery 是逐请求选择，不改变 SSH 的 `agent_route`。

## IPC 和进程边界

`age.sock` 使用 4 字节长度前缀的有界 v1 JSON frame。每个连接只处理一个请求，并通过 macOS
内核对端凭据限制为同一 EUID。帧大小、连接数和处理时间都有上限；客户端断开会取消对应请求。

public read、设备 probe、hardware 和 recovery 分别使用最小能力的 helper 边界：

- public/probe helper 没有 PIN、登录或私钥接口；
- serial、slot 和目标公钥通过有界 pipe 传递，不进入 argv 或普通环境变量；
- hardware/recovery helper 在读取配置和执行敏感操作前验证父子同用户、相同可执行路径、
  相同代码身份和 Hardened Runtime；
- helper 拒绝调试 entitlement、动态库注入、shell/其他可执行文件直接启动和非 macOS+cgo 构建；
- daemon 使用生命周期 pipe 约束 helper；父进程退出时，helper 终止自己的进程组；
- 超时、取消和客户端断开都会执行进程回收，即使底层同步 cgo/SDK 调用不响应 context。

## 状态与错误分类

`yubitouch status --json` 的 age 字段只有：

```text
age_configured
age_socket_reachable
age_recovery_configured
age_backend
age_result
last_age_at
```

`age_backend` 为 `none`、`hardware` 或 `recovery`。`age_configured` 只表示存在 age 配置段，
`age_recovery_configured` 只表示存在 recovery 配置，不证明 1Password item 可读取或 identity
匹配。`age_socket_reachable` 只表示 socket 可连接。

持久化的 `age_result` 是最后一个事件，不是完整审计历史；并发请求可以覆盖它。`started` 只
表示 backend 已被选择并开始尝试，hardware 请求此时甚至可能仍在等待全局 PIV 队列，不能
证明 PIN、UI 或 ECDH 已经开始。成功为 `success`，失败只会持久化以下分类：

| 分类 | 含义 |
|---|---|
| `invalid_request`、`configuration` | identity/stanza/profile 或本机配置不一致 |
| `canceled`、`timeout` | 客户端、UI 或服务生命周期取消/超时 |
| `device_not_detected` | 明确缺卡，但没有可用 recovery 路径 |
| `probe_unavailable`、`target_mismatch` | 探测不可信或目标不匹配 |
| `pin_failed`、`hardware_failed` | PIN/provider 或 hardware 操作失败 |
| `recovery_unavailable`、`recovery_failed` | recovery 无法启动/解析，或恢复操作失败 |
| `internal` | helper、协议或内部不变量失败 |

`unauthorized`、`busy`、`protocol_failure` 和 `daemon_unavailable` 也是插件可见的预定义 IPC
错误，但发生在 service 状态事件之外，不会成为持久化的 `age_result`。触摸未完成时，底层
YKCS11 也可能先返回 `hardware_failed`，不能依赖每次都得到外层 `timeout`。

状态和 JSONL 日志不包含 serial、slot、key ID、公钥、完整 reference、identity、file key、shared
secret、密文内容或底层任意错误字符串。

## 密钥和密文生命周期

### 增加 recovery

重新运行 `configure` 并生成新的 recipient。原 identity 保持不变。此前使用 hardware-only
recipient 创建的密文没有 recovery wrap，缺卡时不能恢复；需要用新 recipient 重新加密。

### 轮换 recovery

生成新的 recovery identity/recipient 后更新配置并重新生成组合 recipient。新密文只包含新的
recovery wrap。旧密文仍可通过 hardware 解密；缺卡恢复只接受当前配置中完全匹配的 recovery
key ID。删除 recovery 配置后，新 recipient 只有 hardware 路径。

在确认旧密文已经迁移前，保留恢复旧 profile 所需的受保护 recovery 资料。单纯更新公开
recipient 不会改写现有密文。

当前没有通过环境变量清空 recovery 的语义：空值会被忽略，provider `none` 会被拒绝。需要
禁用 recovery 时，应停止 daemon，原子删除配置中的 `.age.recovery`，重新生成只有 hardware
路径的 recipient，再启动服务：

```sh
(
  set -eu
  yubitouch stop
  config_path="${YUBITOUCH_CONFIG:-$HOME/.ssh/yubitouch/config.json}"
  temporary_path="$(mktemp "${config_path}.XXXXXX")"
  trap 'rm -f "$temporary_path"' EXIT HUP INT TERM

  jq 'del(.age.recovery)' "$config_path" > "$temporary_path"
  chmod 600 "$temporary_path"
  mv "$temporary_path" "$config_path"
  trap - EXIT HUP INT TERM

  yubitouch age recipient > recipient.hardware-only.txt
  chmod 600 recipient.hardware-only.txt
  yubitouch ensure
)
```

禁用 recovery 不会移除现有密文中的 recovery stanza，但当前配置不会再使用它。

### 更换硬件 key

serial、slot 或 algorithm 变化时，`configure` 会自动清除 `age.public_key` 缓存。同一 serial
和 slot 中直接替换 key 时，当前版本无法只根据配置发现变化。必须停止 daemon、只删除公开
缓存、插入唯一的目标设备、重新生成 recipient/identity，再重启服务：

```sh
(
  set -eu
  yubitouch stop
  config_path="${YUBITOUCH_CONFIG:-$HOME/.ssh/yubitouch/config.json}"
  temporary_path="$(mktemp "${config_path}.XXXXXX")"
  trap 'rm -f "$temporary_path"' EXIT HUP INT TERM

  jq 'del(.age.public_key)' "$config_path" > "$temporary_path"
  chmod 600 "$temporary_path"
  mv "$temporary_path" "$config_path"
  trap - EXIT HUP INT TERM

  yubitouch age recipient > recipient.new.txt
  yubitouch age identity > identity.new.txt
  chmod 600 identity.new.txt
  yubitouch ensure
)
```

核对新描述符后再替换分发中的 recipient。hardware key 变化会同时改变 profile ID、hardware
key ID、recipient 和 identity；当前新 profile 不会自动接受旧密文，即使旧密文包含 recovery
stanza。轮换前应迁移/重新加密旧密文并保留旧硬件。确需从旧 recovery 恢复时，还必须恢复
匹配旧 hardware profile 的配置和 identity，并确保探测状态允许进入 recovery。

## 安全性质与限制

### 硬件与 recovery 是 OR 关系

hardware 和 recovery 任一私钥都足以解密同一 file key。启用 recovery 后，整份密文的整体
安全级别不会高于 1Password 软件恢复路径。不要把 recovery 描述为 YubiKey 私钥的备份副本；
它必须是独立 key。

### Recovery secret 的内存限制

1Password Go SDK 以不可变 Go `string` 返回 secret，无法可靠原地清零。YubiTouch 通过禁用
core dump、尽力锁定/清零可变缓冲区、缩短 helper 生命周期和进程退出缩小暴露范围，但不能
提供硬件级不可导出保证。

### 1Password 授权窗口

1Password SDK v0.4.0 的 macOS backend 不响应调用方 `context.Context` 取消。YubiTouch 在
超时、客户端断开或 helper 异常时仍会回收自己的 helper 和进程组，但由 1Password 拥有的
授权窗口可能继续显示，需要用户手动取消。外部窗口残留不等于 helper 泄漏。

### 同一 UID 和 session 复用

私有 age socket 只能把调用者限制到同一 UID。已认证 hardware session 有效期间，同 UID 恶意
进程可以提交绑定到当前 profile 的解密请求并等待用户触摸。每次 ECDH 的物理触摸是强制授权
门；原生 UI 中的请求程序名称只是 best-effort 辅助判断，解析失败时会降级，不是访问控制或
程序身份认证。session 复用意味着后续请求不再由 PIN 再次确认。

YubiTouch 不能防御已经完全控制当前 macOS 用户或 root 的恶意软件。

### 调试输出

不要对真实数据设置 `AGEDEBUG=plugin`。该上游开关可能输出插件协议内容和 file key，YubiTouch
无法替 age 过滤或清理这些数据。

## 相关文档

- [age 使用教程](age-tutorial.md)
- [项目安装、SSH 和通用配置](../README.md)
- [真实环境验证矩阵](verification.md#age-插件21)
