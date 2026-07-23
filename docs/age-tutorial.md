# 使用 YubiTouch 保护 age 文件

本教程从一个已经写入 YubiKey PIV 的 X25519 key 开始，完成以下工作：

- 让 `age` 使用 YubiKey 完成硬件解密；
- 可选地增加一把保存在 1Password 中的独立恢复密钥；
- 验证加密不依赖 YubiKey、daemon 或 1Password；
- 理解正常操作中应出现的 PIN、1Password 和触摸界面。

需要先了解实现行为和安全边界时，参阅 [age 功能参考](age-reference.md)。真实硬件和
1Password 的发布验收记录位于 [验证矩阵](verification.md#age-插件21)。

## 开始前

当前真实验收环境是 macOS arm64、YubiKey 5.7.4、YKCS11 2.7.3、age v1.3.1 和
1Password SDK v0.4.0。YubiTouch 需要从可信源码构建并使用 Hardened Runtime 签名；直接
`go build` 的未加固二进制不能运行私钥 helper。

开始前确认：

1. 已按 [README 的安装步骤](../README.md#安装与首次使用)安装并配置 YubiTouch；
2. `yubitouch` 和精确命名的 `age-plugin-yubitouch` 都能从 `PATH` 找到；
3. 目标 YubiKey 的一个 PIV 槽位中已经存在 X25519 key；
4. 该 key 的策略必须是 PIN `ONCE`、touch `ALWAYS`；
5. 如需 recovery，1Password 已启用 **Settings > Developer > Integrate with other apps**。

age 不是一套绕过基础配置的独立 daemon：现有配置仍必须包含 README 中准备的 SSH 9A 公钥、
PIN provider 和 YKCS11 路径。age X25519 key 使用另一个明确槽位，但复用同一个 YubiTouch
服务和 PIN provider。

> YubiTouch 只读取和使用已有 PIV key，不生成、导入、覆盖、删除或同步 key。不要对已包含
> 重要 key 的槽位执行 `ykman piv keys generate`、`import` 或 `delete`。错误 PIN 会消耗有限
> 重试次数；不要用日常设备试错。

age 的 X25519 key 与 SSH 使用的 9A ED25519 key 是两把不同的 key。退休槽 `82` 到 `95`
适合与 SSH key 分开；本教程使用 `82` 作为示例。YubiTouch 也接受 `9a`、`9c`、`9d`、`9e`
和 `82` 到 `95`，但不会替用户判断某个槽位能否覆盖。

## 1. 检查安装和 PIV key

```sh
yubitouch version
age --version
ykman --version
yubico-piv-tool --version
ykman piv keys info 82
```

确认 CLI 和插件来自同一个推荐安装位置：

```sh
(
  set -eu
  cli_path="$(command -v yubitouch)"
  plugin_path="$(command -v age-plugin-yubitouch)"
  test "$cli_path" = "$HOME/.local/bin/yubitouch"
  test "$plugin_path" = "$HOME/.local/bin/age-plugin-yubitouch"
  test -x "$cli_path"
  test -x "$plugin_path"
  test "$(readlink "$cli_path")" = \
    /Applications/YubiTouch.app/Contents/MacOS/yubitouch
  test "$(readlink "$plugin_path")" = \
    /Applications/YubiTouch.app/Contents/MacOS/age-plugin-yubitouch
)
```

最后一条命令必须指向准备使用的槽位，并显示 `Algorithm: X25519`、
`PIN required for use: ONCE` 和 `Touch required for use: ALWAYS`。策略不匹配时硬件 helper 会
失败闭合；YubiTouch 不会修改策略。不要把完整设备 serial、PIN 或命令输出粘贴到公开 Issue。
下一步会在 fail-fast 子 shell 中读取唯一连接设备的 serial，不会把它打印到终端。如果连接了
多把设备，配置会在写入前失败；拔下非目标设备后重试，不要让脚本自动选择其中一把。

## 2. 配置硬件主路径

配置只在显式运行 `yubitouch configure` 时从环境变量合并并保存。daemon 不读取当前交互式
shell，也不接受每次解密的临时设备覆盖。

```sh
(
  set -eu
  age_serial="$(ykman list --serials 2>/dev/null)"
  if ! printf '%s\n' "$age_serial" |
    awk 'NF { count++; if ($0 ~ /^[1-9][0-9]*$/ && $0 <= 4294967295) valid=1 }
         END { exit !(count == 1 && valid) }'; then
    echo "expected exactly one YubiKey with a canonical numeric serial" >&2
    exit 1
  fi

  YUBITOUCH_AGE_SERIAL="$age_serial" \
  YUBITOUCH_AGE_SLOT='82' \
  YUBITOUCH_AGE_ALGORITHM='x25519' \
    yubitouch configure
)
```

这一步只保存目标，不读取 age 私钥、不执行 ECDH，也不修改 YubiKey；不应出现 PIN、
1Password 或触摸 UI。命令输出中的 `Public key: SHA256:...` 是基础 SSH 9A key 的指纹，不是
age X25519 key。配置文件仍位于 `~/.ssh/yubitouch/config.json`，权限应为 `0600`。

## 3. 生成 recipient 和 identity

创建一个只对当前用户开放的目录：

```sh
AGE_DIR="$HOME/.config/yubitouch/age"
RECIPIENT="$AGE_DIR/recipient.txt"
IDENTITY="$AGE_DIR/identity.txt"

(
  set -eu
  umask 077
  mkdir -p "$AGE_DIR"
  chmod 700 "$AGE_DIR"

  recipient_tmp="$(mktemp "$AGE_DIR/.recipient.XXXXXX")"
  identity_tmp="$(mktemp "$AGE_DIR/.identity.XXXXXX")"
  trap 'rm -f "$recipient_tmp" "$identity_tmp"' EXIT HUP INT TERM

  yubitouch age recipient > "$recipient_tmp"
  yubitouch age identity > "$identity_tmp"

  test "$(awk 'END { print NR + 0 }' "$recipient_tmp")" -eq 1
  test "$(awk 'END { print NR + 0 }' "$identity_tmp")" -eq 1
  case "$(sed -n '1p' "$recipient_tmp")" in age1yubitouch1*) ;; *) exit 1 ;; esac
  case "$(sed -n '1p' "$identity_tmp")" in AGE-PLUGIN-YUBITOUCH-1*) ;; *) exit 1 ;; esac

  chmod 600 "$recipient_tmp" "$identity_tmp"
  mv "$recipient_tmp" "$RECIPIENT"
  mv "$identity_tmp" "$IDENTITY"
  trap - EXIT HUP INT TERM
)
```

首次运行时必须插入目标 YubiKey。YubiTouch 会在一个只读 helper 中读取并校验槽位公钥，
然后把公开值缓存到配置中。这个过程不请求 PIN、不执行私钥操作，也不显示触摸提示。后续生成
相同描述符时可以使用缓存，不要求设备在场。

- `recipient.txt` 是公开的组合 recipient，以 `age1yubitouch1...` 开头，可以分发给加密端；
- `identity.txt` 是本机插件描述符，以 `AGE-PLUGIN-YUBITOUCH-1...` 开头，不包含私钥、serial、
  slot、PIN 或 1Password reference，但应作为本机配置文件保管。

明确重启 LaunchAgent，让 daemon 读取新配置和公钥缓存：

```sh
yubitouch reload
yubitouch status
```

LaunchAgent 尚未注册时，先运行一次 `yubitouch ensure`。不要只更新磁盘上的 App 或配置而
继续使用旧 daemon。`yubitouch doctor` 可以检查通用依赖和 recovery reference 语法，但不会
解析 recovery item，也不会代替 X25519 slot、policy 或真实加解密验证。

## 4. 加密文件

先用一份无敏感内容的文件验证流程：

```sh
printf 'YubiTouch age test\n' > "$AGE_DIR/plaintext.txt"

age -R "$RECIPIENT" \
  -o "$AGE_DIR/plaintext.txt.age" \
  "$AGE_DIR/plaintext.txt"
```

加密只读取 recipient 中的公开材料，不连接 YubiTouch daemon、YubiKey 或 1Password。保存好
recipient 后，即使设备已拔出或 daemon 已停止也能继续加密。

age 会覆盖 `-o` 指定的已有文件。对真实数据操作前先核对输入、输出不是同一路径，并为现有
输出选择新名称或完成备份。

对真实文件使用相同形式：

```sh
age -R "$RECIPIENT" -o document.txt.age document.txt
```

## 5. 使用 YubiKey 解密

保持目标 YubiKey 连接并运行：

```sh
(
  set -eu
  hardware_output="$(mktemp "$AGE_DIR/hardware-decrypted.XXXXXX")"
  trap 'rm -f "$hardware_output"' EXIT HUP INT TERM

  if age -d -i "$IDENTITY" \
       -o "$hardware_output" \
       "$AGE_DIR/plaintext.txt.age" &&
     cmp -s "$AGE_DIR/plaintext.txt" "$hardware_output"; then
    echo 'hardware_verified=yes'
  else
    echo 'hardware_verified=no' >&2
    exit 1
  fi
)
```

age 在等待插件完成时可能向 stderr 显示 `age: waiting on yubitouch plugin...`；这不是失败。
以命令退出状态和 `hardware_verified=yes` 为准。

第一次硬件解密的正常交互顺序是：

1. 配置为 `prompt` 时显示安全 PIN 输入框；配置为 `1password` 时先显示一次 1Password 授权；
2. PIN provider 完成且 YKCS11 login 成功后，才显示 YubiTouch 的“age 解密”触摸提示；
3. 实际触摸 YubiKey；
4. 解密完成后触摸面板自动关闭。

同一 daemon 可以保留已认证的硬件 session。后续请求可能不再询问 PIN 或显示 1Password
授权，但每次 X25519 ECDH 仍会显示独立的触摸提示并要求实际触摸。

这里的 `pin_provider=1password` 只在硬件已连接时读取 PIV PIN；下节的 age recovery 只在明确
缺卡时读取软件 X25519 identity；可选的 1Password SSH Agent 缺卡路由又是第三套独立功能。

PIN 或 1Password 授权没有结束时，不应提前显示触摸面板。PIN 失败、取消或 YKCS11 login
失败也不应短暂显示触摸提示。

## 6. 可选：增加 1Password recovery

recovery key 必须是与硬件 key 独立的原生 age X25519 identity。两条路径是 OR 关系：得到
任意一把私钥就能独立解密，因此启用 recovery 会把整体安全级别降低到软件恢复路径。

### 6.1 生成独立恢复 identity

在私有目录生成一把临时本地 recovery identity：

```sh
RECOVERY_IDENTITY="$AGE_DIR/recovery-identity.txt"
RECOVERY_RECIPIENT="$AGE_DIR/recovery-recipient.txt"

(
  set -eu
  umask 077

  if [ -e "$RECOVERY_IDENTITY" ] || [ -e "$RECOVERY_RECIPIENT" ]; then
    echo 'recovery key files already exist; refusing to reuse or overwrite them' >&2
    exit 1
  fi

  recovery_tmp="$(mktemp -d "$AGE_DIR/.recovery-key.XXXXXX")"
  identity_tmp="$recovery_tmp/identity.txt"
  recipient_tmp="$recovery_tmp/recipient.txt"
  trap 'rm -f "$identity_tmp" "$recipient_tmp"; rmdir "$recovery_tmp"' \
    EXIT HUP INT TERM

  age-keygen -o "$identity_tmp"
  age-keygen -y "$identity_tmp" > "$recipient_tmp"

  test "$(awk '/^AGE-SECRET-KEY-1/ { count++ } END { print count + 0 }' \
    "$identity_tmp")" -eq 1
  test "$(awk 'END { print NR + 0 }' "$recipient_tmp")" -eq 1
  case "$(sed -n '1p' "$recipient_tmp")" in age1*) ;; *) exit 1 ;; esac

  chmod 600 "$identity_tmp" "$recipient_tmp"
  mv "$identity_tmp" "$RECOVERY_IDENTITY"
  mv "$recipient_tmp" "$RECOVERY_RECIPIENT"
  rmdir "$recovery_tmp"
  trap - EXIT HUP INT TERM
)
```

这个命令块不会覆盖或默认复用已有 recovery key 文件。任一目标已经存在时，先核对它的用途，
再明确决定沿用现有 key、改用新的文件名，或按轮换流程处理。

在 1Password 中创建专用 item 和字段，把 `recovery-identity.txt` 中完整且唯一的
`AGE-SECRET-KEY-1...` 行保存为字段值。该字段必须恰好是规范的 74 字符单行 identity，不能
包含 `age-keygen` 注释、空格或额外换行。复制该字段的 secret reference，形式为
`op://<vault>/<item>/<field>`。不要把 identity 粘贴到终端命令、配置、Issue、日志或普通
环境变量中。

在确认 1Password item 和真实 recovery 解密都成功前，保留这个权限为 `0600` 的临时文件。

### 6.2 配置 recovery

`onepassword_account` 是 PIN provider 和 age recovery 共用的全局字段。如果
`pin_provider=1password`，recovery item 必须位于当前配置正在使用的同一个 account；不要为
recovery 随意换成另一个 account，否则原有 PIV PIN reference 会在下一次硬件登录时失败。

将下面的占位值替换为当前配置使用的 1Password account 和字段 reference。公开 recipient 从
已经生成并验证为非空单行的文件读取：

```sh
(
  set -eu
  test "$(awk 'END { print NR + 0 }' "$RECOVERY_RECIPIENT")" -eq 1
  recovery_public="$(sed -n '1p' "$RECOVERY_RECIPIENT")"
  case "$recovery_public" in age1*) ;; *) exit 1 ;; esac

  YUBITOUCH_1PASSWORD_ACCOUNT='<existing account name or UUID>' \
  YUBITOUCH_AGE_RECOVERY_PROVIDER='1password' \
  YUBITOUCH_AGE_RECOVERY_IDENTITY_REF='op://<vault>/<item>/<field>' \
  YUBITOUCH_AGE_RECOVERY_RECIPIENT="$recovery_public" \
    yubitouch configure
)
```

配置只保存 account、secret reference 和公开 recipient，不保存恢复私钥。以下变量如果非空会
被明确拒绝：

```text
YUBITOUCH_AGE_RECOVERY_IDENTITY
YUBITOUCH_AGE_RECOVERY_PRIVATE_KEY
YUBITOUCH_AGE_RECOVERY_SECRET
```

`configure` 只校验 account、reference 和 recipient 的本地格式，不访问 1Password，也不应
显示授权或触摸 UI。第一次真实缺卡解密才会解析指定 item。

重新生成组合 recipient，并重载 daemon：

```sh
(
  set -eu
  umask 077
  recipient_tmp="$(mktemp "$AGE_DIR/.recipient.XXXXXX")"
  identity_check="$(mktemp "$AGE_DIR/.identity-check.XXXXXX")"
  trap 'rm -f "$recipient_tmp" "$identity_check"' EXIT HUP INT TERM

  yubitouch age recipient > "$recipient_tmp"
  yubitouch age identity > "$identity_check"

  test "$(awk 'END { print NR + 0 }' "$recipient_tmp")" -eq 1
  case "$(sed -n '1p' "$recipient_tmp")" in age1yubitouch1*) ;; *) exit 1 ;; esac
  cmp -s "$IDENTITY" "$identity_check" || {
    echo 'identity changed while only recovery was updated' >&2
    exit 1
  }

  chmod 600 "$recipient_tmp"
  mv "$recipient_tmp" "$RECIPIENT"
  rm -f "$identity_check"
  trap - EXIT HUP INT TERM
) && yubitouch reload
```

identity 只绑定硬件 profile，因此 recovery 变化时应保持稳定；recipient 现在包含 hardware 和
recovery 两条公开路径。启用 recovery 前已经存在的密文不会自动获得 recovery wrap，必须使用
新的 recipient 重新加密，才能在缺卡时恢复。

```sh
age -R "$RECIPIENT" \
  -o "$AGE_DIR/plaintext-with-recovery.age" \
  "$AGE_DIR/plaintext.txt"
```

### 6.3 验证缺卡恢复

1. 拔出所有 YubiKey；
2. 等待 `yubitouch status` 显示设备未检测到；
3. 执行同一个 identity 的解密命令：

```sh
yubitouch status

(
  set -eu
  recovery_output="$(mktemp "$AGE_DIR/recovery-decrypted.XXXXXX")"
  trap 'rm -f "$recovery_output"' EXIT HUP INT TERM

  if age -d -i "$IDENTITY" \
       -o "$recovery_output" \
       "$AGE_DIR/plaintext-with-recovery.age" &&
     cmp -s "$AGE_DIR/plaintext.txt" "$recovery_output"; then
    echo 'recovery_verified=yes'
  else
    echo 'recovery_verified=no; keep the local recovery identity' >&2
    exit 1
  fi
)
```

正常现象是只出现一次 1Password 授权，不出现 YubiTouch 触摸提示。YubiTouch 必须连续两次
明确确认目标设备为 `not_detected` 后才会启动一次性 recovery helper。age recovery 不改变
SSH 的 `agent_route`。

只有命令明确输出 `recovery_verified=yes`，并确认 1Password item 与其他受保护恢复方案可靠后，
才手动删除 `$HOME/.config/yubitouch/age/recovery-identity.txt`。教程不自动删除这份唯一临时私钥。
普通文件删除也不能保证从 APFS snapshot 或备份中抹除旧副本；生成和导入时应使用受保护的
本机存储，并避免让它进入同步或备份目录。

## 7. 日常使用

加密端只需要公开 recipient：

```sh
age -R "$HOME/.config/yubitouch/age/recipient.txt" \
  -o archive.tar.age archive.tar
```

解密端需要本机 identity、运行中的 YubiTouch daemon，以及硬件或 recovery 中至少一条可用路径：

```sh
age -d \
  -i "$HOME/.config/yubitouch/age/identity.txt" \
  -o archive.restored.tar archive.tar.age
```

解密的 `-o` 同样会覆盖已有文件；不要把输出指回仍需保留的原始文件。

不要在真实数据上设置 `AGEDEBUG=plugin`。这是 age 自己的调试开关，可能把插件协议内容和
file key 写到终端，超出 YubiTouch 的脱敏日志边界。

## 8. 路径选择规则

| 当前状态 | 选择的路径 | 用户交互 | 是否尝试另一条路径 |
|---|---|---|---|
| 目标 YubiKey 已连接 | hardware | 首次 PIN/1Password PIN provider；每次触摸 | 否 |
| 连续确认目标设备未连接，且密文与配置都包含 recovery | recovery | 一次 1Password 授权；无触摸提示 | 否 |
| 插入其他设备或 serial/slot/public key 不匹配 | 失败闭合 | 无 recovery 授权 | 否 |
| 探测失败或状态不明 | 失败闭合 | 无 recovery 授权 | 否 |
| PIN、触摸、YKCS11、ECDH 或解包失败 | hardware 失败闭合 | 只结束当前请求 | 否 |

一旦请求选择 hardware，同一次请求绝不会改走 recovery。这避免攻击者通过阻断 PIN、触摸或
设备通信来强制读取 1Password 中的恢复私钥。

## 9. 状态和排障

```sh
yubitouch status
yubitouch status --json
yubitouch doctor
```

age 相关状态只包含：是否配置、socket 是否可达、是否配置 recovery，以及上一次请求的
`age_backend`、`age_result` 和时间。它不会输出 serial、slot、公钥、key ID、recovery reference
或底层错误文本。

| 现象 | 处理方式 |
|---|---|
| age 找不到插件 | 确认 `command -v age-plugin-yubitouch` 指向 App bundle 中精确同名的入口。 |
| identity 无法连接 daemon | 运行 `yubitouch ensure`，确认 `age_socket_reachable=true`。 |
| 首次生成 recipient 失败 | 插入唯一的目标设备，核对 slot 中是 X25519 key；该读取不会要求 PIN。 |
| 缺卡但没有进入 recovery | 确认设备状态明确为 `not_detected`、配置包含 recovery，且密文由包含 recovery 的新 recipient 创建。 |
| hardware 失败后没有进入 recovery | 这是预期的失败闭合行为；修复 PIN、触摸、设备或 YKCS11 问题后重新发起请求。 |
| 1Password 超时后授权窗口仍显示 | YubiTouch 已回收自己的 helper；在 1Password 中手动取消该窗口。 |
| 同一 serial/slot 换 key 后 mismatch | 按 [功能参考中的硬件 key 更换步骤](age-reference.md#更换硬件-key)刷新公钥缓存和描述符。 |

更完整的状态分类、session 失效条件、密文兼容性和安全说明见
[age 功能参考](age-reference.md)。
