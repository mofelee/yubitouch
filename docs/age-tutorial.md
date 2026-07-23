# 使用 YubiTouch 保护 age 文件

这是一份面向已经安全配置好 PIV X25519 key、第一次使用 YubiTouch age 功能的操作教程。
完成后，你可以：

- 使用公开 recipient 加密文件，加密时不需要插入 YubiKey；
- 使用 YubiKey 中已有的 PIV X25519 key 解密；
- 可选地把一把独立的恢复密钥保存在 1Password 中，在明确缺卡时恢复文件。

先记住三个概念：recipient 是可以分发的公开加密地址；identity 是本机交给插件的描述符；真正
的硬件私钥始终留在 YubiKey 中，不会写入 identity 文件。

本文只保留实际使用所需的命令。路径选择、session 复用、协议格式和安全边界见
[age 功能参考](age-reference.md)，发布级验收记录见
[验证矩阵](verification.md#age-插件21)。

## 开始前

请先按 [README 的安装步骤](../README.md#安装与首次使用)完成 YubiTouch 的基础安装。本文
假设：

- 使用 macOS arm64；
- `yubitouch`、`age-plugin-yubitouch`、`age`、`ykman` 和 `yubico-piv-tool` 已安装；
- YubiKey 的 PIV 槽位 `82` 中已经有一把 X25519 key；
- 这把 key 的策略是 PIN `ONCE`、touch `ALWAYS`。

示例使用槽位 `82`。使用其他槽位时，把命令中的 `82` 换成实际槽位。
age 使用的 X25519 key 与 SSH 默认使用的 9A ED25519 key 是两把不同的 key。

> YubiTouch 只使用已经存在的 PIV key，不会生成、导入、覆盖或删除 key。本教程也不会提供
> 覆盖槽位的命令。错误 PIN 会消耗有限的重试次数，请先确认设备和槽位正确。

如果设备中还没有符合条件的 X25519 key，本教程无法继续。创建全新 key 时，先按
[设备内生成教程](piv-x25519-generate.md)操作；需要保留已有 PKCS#8 X25519 私钥时，改用
[独立导入教程](piv-x25519-import.md)。两份教程都会先确认空槽，不要临时复制一条可能覆盖
现有槽位的命令。

## 1. 检查工具和 PIV key

先查看各工具版本：

```sh
yubitouch version
age --version
ykman --version
yubico-piv-tool --version
```

确认主程序和 age 插件来自同一个 App：

```sh
command -v yubitouch
readlink "$(command -v yubitouch)"

command -v age-plugin-yubitouch
readlink "$(command -v age-plugin-yubitouch)"
```

推荐安装的结果应分别指向：

```text
$HOME/.local/bin/yubitouch
/Applications/YubiTouch.app/Contents/MacOS/yubitouch
$HOME/.local/bin/age-plugin-yubitouch
/Applications/YubiTouch.app/Contents/MacOS/age-plugin-yubitouch
```

只连接目标 YubiKey，然后查看 serial：

```sh
ykman list --serials
```

这里应只有一行十进制数字。不要把完整 serial、PIN 或配置内容粘贴到公开 Issue。
把下面的 `<YubiKey serial>` 换成刚才看到的数字，再检查准备使用的 PIV 槽位：

```sh
ykman --device '<YubiKey serial>' piv keys info 82
```

继续之前，输出中必须包含：

```text
Algorithm: X25519
PIN required for use: ONCE
Touch required for use: ALWAYS
```

如果算法或策略不同，请停止。YubiTouch 会拒绝使用不符合要求的 key，也不会替你修改策略。

## 2. 配置硬件解密路径

使用上一步确认过的同一 serial：

```sh
YUBITOUCH_AGE_SERIAL='<YubiKey serial>' \
YUBITOUCH_AGE_SLOT='82' \
YUBITOUCH_AGE_ALGORITHM='x25519' \
  yubitouch configure
```

这一步只保存目标设备和槽位，不读取私钥，也不会出现 PIN、1Password 或触摸提示。命令显示的
`Public key: SHA256:...` 是基础 SSH 9A key 的指纹，不是 age X25519 key。

## 3. 生成 recipient 和 identity

先创建保存 age 配置的私有目录：

```sh
mkdir -p "$HOME/.config/yubitouch/age"
chmod 700 "$HOME/.config/yubitouch/age"
```

先把两个描述符生成到 `.new` 文件。正式文件或同名 `.new` 文件已经存在时，请先停止并核对，
不要直接覆盖：

```sh
yubitouch age recipient \
  > "$HOME/.config/yubitouch/age/recipient.txt.new"
yubitouch age identity \
  > "$HOME/.config/yubitouch/age/identity.txt.new"
```

第一次执行时必须插入目标 YubiKey。YubiTouch 只读取槽位公钥并把它缓存到配置中；这个过程
不需要 PIN，不会执行私钥操作，也不会显示触摸提示。

查看新文件的第一行：

```sh
sed -n '1p' "$HOME/.config/yubitouch/age/recipient.txt.new"
sed -n '1p' "$HOME/.config/yubitouch/age/identity.txt.new"
```

正常格式分别是 `age1yubitouch1...` 和 `AGE-PLUGIN-YUBITOUCH-1...`。两条生成命令都成功且
格式正确后，再将它们作为正式文件：

```sh
mv "$HOME/.config/yubitouch/age/recipient.txt.new" \
  "$HOME/.config/yubitouch/age/recipient.txt"
mv "$HOME/.config/yubitouch/age/identity.txt.new" \
  "$HOME/.config/yubitouch/age/identity.txt"
chmod 600 "$HOME/.config/yubitouch/age/recipient.txt" \
  "$HOME/.config/yubitouch/age/identity.txt"
```

recipient 只包含公开材料，可以交给加密端。identity 不包含私钥、serial、PIN 或 1Password
reference，但它依赖当前机器上的 YubiTouch 配置，应作为本机配置文件保管。

需要更新 key 或 recovery 时，请按
[功能参考中的密钥生命周期](age-reference.md#密钥和密文生命周期)处理，不要直接重新运行本节
覆盖正式文件。

让正在运行的 daemon 读取新配置：

```sh
yubitouch reload
yubitouch status
```

如果 LaunchAgent 尚未启动，先运行 `yubitouch ensure`。

## 4. 加密一个测试文件

创建一份无敏感内容的测试文件：

```sh
printf 'YubiTouch age test\n' > "$HOME/.config/yubitouch/age/plaintext.txt"
```

使用公开 recipient 加密：

```sh
age -R "$HOME/.config/yubitouch/age/recipient.txt" \
  -o "$HOME/.config/yubitouch/age/plaintext.txt.age" \
  "$HOME/.config/yubitouch/age/plaintext.txt"
```

这里 `-R` 指定 recipient 文件，`-o` 指定输出文件，最后一个参数是要加密的输入文件。
加密只需要 recipient 中的公开信息，不连接 YubiTouch daemon、YubiKey 或 1Password。因此
这一步不应出现 PIN、授权或触摸提示。对真实文件操作时，请为已有输出做好备份或换一个新文件名。

## 5. 使用 YubiKey 解密

保持目标 YubiKey 连接，然后执行：

```sh
age -d \
  -i "$HOME/.config/yubitouch/age/identity.txt" \
  -o "$HOME/.config/yubitouch/age/plaintext.decrypted.txt" \
  "$HOME/.config/yubitouch/age/plaintext.txt.age"
```

`-d` 表示解密，`-i` 指定 YubiTouch identity，`-o` 指定解密后的输出文件。

第一次硬件解密的正常交互顺序是：

1. `pin_provider=prompt` 时出现 PIN 输入框；`pin_provider=1password` 时出现一次 1Password
   授权；
2. PIN provider 完成并且 YKCS11 login 成功；
3. YubiTouch 显示“age 解密”触摸提示；
4. 实际触摸 YubiKey；
5. 解密完成，触摸提示自动关闭。

PIN 或 1Password 授权结束前，不应提前显示触摸提示。age 在等待插件时可能显示
`age: waiting on yubitouch plugin...`，这是正常等待信息。

比较原文件和解密结果：

```sh
cmp "$HOME/.config/yubitouch/age/plaintext.txt" \
  "$HOME/.config/yubitouch/age/plaintext.decrypted.txt"
```

`cmp` 没有输出并返回到提示符，表示内容完全一致。

## 6. 再解密一次

同一个 daemon 会复用已经认证的硬件 session。换一个输出文件，再执行一次：

```sh
age -d \
  -i "$HOME/.config/yubitouch/age/identity.txt" \
  -o "$HOME/.config/yubitouch/age/plaintext.decrypted-again.txt" \
  "$HOME/.config/yubitouch/age/plaintext.txt.age"
```

正常情况下，这次不再要求 PIN 或 1Password 授权，但仍会显示一次触摸提示，并且必须实际触摸
YubiKey。设备拔插、配置 reload、daemon 重启或硬件 helper 错误会使 session 失效。如果一个
取消或超时的请求已经使用了当前 hardware session，该 session 也会失效；下一次解密会重新
请求 PIN。

## 7. 日常使用

加密只需要公开 recipient：

```sh
age -R "$HOME/.config/yubitouch/age/recipient.txt" \
  -o archive.tar.age archive.tar
```

解密使用本机 identity：

```sh
age -d \
  -i "$HOME/.config/yubitouch/age/identity.txt" \
  -o archive.restored.tar archive.tar.age
```

不需要缺卡恢复的用户到这里已经完成配置。不要把输出路径指回仍需保留的输入文件，也不要对
真实数据设置 `AGEDEBUG=plugin`。age 的这个调试开关可能把插件协议内容和 file key 写到终端。

## 8. 可选：增加 1Password recovery

recovery 是一把独立的软件 X25519 key，不是 YubiKey 私钥的副本。hardware 和 recovery 是
OR 关系：任意一把私钥都可以解密，所以启用 recovery 后，文件的整体安全级别不会高于
1Password 恢复路径。

不需要缺卡恢复时，可以跳过本节。

继续前，请安装并登录 1Password 桌面端，然后启用
**Settings > Developer > Integrate with other apps**。

### 8.1 创建 recovery key

下面两个文件必须是新文件。任一文件已经存在时先停止，不要覆盖，也不要默认把旧 key 当作
新 key 使用。

```sh
age-keygen -o "$HOME/.config/yubitouch/age/recovery-identity.txt"
chmod 600 "$HOME/.config/yubitouch/age/recovery-identity.txt"
age-keygen -y "$HOME/.config/yubitouch/age/recovery-identity.txt" \
  > "$HOME/.config/yubitouch/age/recovery-recipient.txt.new"
```

`age-keygen -o` 会拒绝覆盖已有 identity。确认下面的输出是一行 `age1...` recipient：

```sh
cat "$HOME/.config/yubitouch/age/recovery-recipient.txt.new"
```

确认后再保存为正式 recipient：

```sh
mv "$HOME/.config/yubitouch/age/recovery-recipient.txt.new" \
  "$HOME/.config/yubitouch/age/recovery-recipient.txt"
chmod 600 "$HOME/.config/yubitouch/age/recovery-recipient.txt"
```

在 1Password 中创建一个专用 item。把 `recovery-identity.txt` 中唯一的
`AGE-SECRET-KEY-1...` 行保存到一个字段中。字段值必须是完整的 74 字符单行，不能包含
`age-keygen` 注释、空格或额外换行。

复制这个字段的 secret reference，格式为：

```text
op://<vault>/<item>/<field>
```

不要把 recovery identity 放进配置、终端命令、Issue、日志或普通环境变量。在完成真实恢复
测试前，保留本机的 `recovery-identity.txt`。

### 8.2 配置 recovery

把下面三个占位值换成实际内容。`<recovery recipient>` 是刚才看到的 `age1...` 单行公钥：

```sh
YUBITOUCH_1PASSWORD_ACCOUNT='<account name or UUID>' \
YUBITOUCH_AGE_RECOVERY_PROVIDER='1password' \
YUBITOUCH_AGE_RECOVERY_IDENTITY_REF='op://<vault>/<item>/<field>' \
YUBITOUCH_AGE_RECOVERY_RECIPIENT='<recovery recipient>' \
  yubitouch configure
```

`onepassword_account` 由硬件 PIN provider 和 age recovery 共用。如果硬件 PIN 已经来自
1Password，这里必须使用同一个 account。

`configure` 只检查配置格式，不访问 1Password，因此不应出现授权或触摸提示。YubiTouch
不会把 recovery 私钥写入配置；任何尝试直接传递私钥的 recovery 环境变量都会被拒绝。

生成一个包含 hardware 和 recovery 两条路径的新 recipient，但先不要覆盖正在使用的文件：

```sh
yubitouch age recipient \
  > "$HOME/.config/yubitouch/age/recipient.txt.new"
sed -n '1p' "$HOME/.config/yubitouch/age/recipient.txt.new"
```

确认输出是一行 `age1yubitouch1...` 后，把它设为今后统一使用的 recipient：

```sh
mv "$HOME/.config/yubitouch/age/recipient.txt.new" \
  "$HOME/.config/yubitouch/age/recipient.txt"
chmod 600 "$HOME/.config/yubitouch/age/recipient.txt"
yubitouch reload
```

原来的 `identity.txt` 不需要更新。从现在开始，第 7 节的日常加密命令会自动使用包含 recovery
的 recipient。启用 recovery 之前创建的密文不会自动获得恢复路径，必须使用更新后的
`recipient.txt` 重新加密。

### 8.3 创建并测试可恢复密文

使用新 recipient 加密测试文件：

```sh
age -R "$HOME/.config/yubitouch/age/recipient.txt" \
  -o "$HOME/.config/yubitouch/age/plaintext-with-recovery.age" \
  "$HOME/.config/yubitouch/age/plaintext.txt"
```

然后：

1. 拔出所有 YubiKey；
2. 等待 `yubitouch status` 显示目标设备未检测到；
3. 执行下面的解密命令。

```sh
yubitouch status

age -d \
  -i "$HOME/.config/yubitouch/age/identity.txt" \
  -o "$HOME/.config/yubitouch/age/plaintext.recovered.txt" \
  "$HOME/.config/yubitouch/age/plaintext-with-recovery.age"
```

正常现象是出现一次 1Password 授权，不出现 YubiTouch 触摸提示，也不改变 SSH 的
`agent_route`。

最后比较恢复结果：

```sh
cmp "$HOME/.config/yubitouch/age/plaintext.txt" \
  "$HOME/.config/yubitouch/age/plaintext.recovered.txt"
```

`recovery-identity.txt` 在本机保留期间，本身就是 1Password 之外的另一条软件解密路径。只有
真实缺卡恢复成功，并确认 1Password item 可用、所需的受保护备份也已安排好之后，才手动移除
这个工作副本。不要在验证前删除它。普通文件删除也无法保证从 APFS snapshot 或备份中抹除
旧副本。

## YubiTouch 如何选择解密路径

| 当前状态 | 结果 | 正常交互 |
|---|---|---|
| 目标 YubiKey 已连接且匹配 | 使用 hardware | 首次 PIN/1Password PIN provider；每次触摸 |
| 连续确认目标设备未连接，且配置和密文都有 recovery | 使用 recovery | 一次 1Password 授权；无触摸 |
| 插入其他设备或 key 不匹配 | 失败闭合 | 不尝试 recovery |
| 探测失败或设备状态不明确 | 失败闭合 | 不尝试 recovery |
| PIN、触摸、YKCS11 或硬件操作失败 | hardware 失败 | 不改走 recovery |

一旦请求选择 hardware，同一次请求不会再改走 recovery。这样可以避免攻击者通过阻断 PIN、
触摸或设备通信，强制读取 1Password 中的恢复私钥。

## 常见问题

| 现象 | 处理方式 |
|---|---|
| age 找不到插件 | 检查 `command -v age-plugin-yubitouch` 和对应的 `readlink` 结果。 |
| identity 无法连接 daemon | 运行 `yubitouch ensure`，再检查 `yubitouch status`。 |
| 首次生成 recipient 失败 | 只连接目标设备，确认槽位中是符合策略的 X25519 key。 |
| PIN/1Password 尚未结束就出现触摸提示 | 这不是预期顺序；记录版本和现象后报告问题。 |
| hardware 失败后没有进入 recovery | 这是预期的失败闭合行为；修复硬件路径后重新解密。 |
| 缺卡但没有进入 recovery | 确认设备状态明确为未检测到，并确认密文由 recovery recipient 创建。 |
| 1Password 超时后授权窗口仍显示 | YubiTouch 已回收 helper；手动取消 1Password 拥有的窗口。 |
| 同一 serial/slot 更换 key 后 mismatch | 按 [更换硬件 key](age-reference.md#更换硬件-key) 刷新描述符。 |

查看不含敏感材料的运行状态：

```sh
yubitouch status
yubitouch status --json
yubitouch doctor
```

更完整的实现行为和限制见 [YubiTouch age 功能参考](age-reference.md)。
