# 把已有 X25519 私钥导入 YubiKey PIV

本教程把一把已经存在的 X25519 私钥导入 YubiKey 的空闲 PIV 槽位，供 YubiTouch age
hardware 路径使用。示例使用退休槽 `82`，并设置 YubiTouch 要求的 PIN `ONCE`、touch
`ALWAYS` 策略。

这是有覆盖风险的 PIV 管理操作。请完整读完“开始前”和“确认空槽”，再执行导入命令。

## 教程范围

本教程的输入是一个 X25519 **PKCS#8 PEM 私钥文件**。推荐使用加密形式，第一行是：

```text
-----BEGIN ENCRYPTED PRIVATE KEY-----
```

未加密 PKCS#8 PEM 的第一行是 `-----BEGIN PRIVATE KEY-----`，也能导入，但它在磁盘上没有
口令保护，不推荐作为迁移文件。`ykman` 5.9.2 还能解析 DER 和 PKCS#12；为了让格式检查和
公钥比对保持明确，本教程只使用 PKCS#8 PEM。

以下内容不能直接传给 `ykman piv keys import`：

- 原生 age identity，例如 `AGE-SECRET-KEY-1...`；
- 只有 32 字节的 raw scalar；
- age recipient，例如 `age1...`；
- OpenSSH 私钥。

原生 age identity 即使经过专门转换并导入，也不会让 YubiTouch identity 自动兼容已有的
原生 age `X25519` stanza。旧文件仍需要原来的 age identity；YubiTouch 创建的是独立的
`age1yubitouch1...` recipient 和 stanza 格式。不要仅为了迁移旧 age 密文而导入同一把 key。

## 开始前

确认以下条件：

- 使用固件 5.7 或更高版本、支持 PIV X25519 的 YubiKey；当前真实验收设备固件为 5.7.4；
- 已安装 `ykman` 5.9.2、OpenSSL 3 和 YKCS11 2.7.3；
- 已按 [README 的 PIV 准备步骤](../README.md#2-配置-yubikey-piv-9a)修改默认 PIN、PUK 和
  Management Key；
- 只连接准备修改的那一把 YubiKey；
- 有另一种可靠的登录和恢复方式；
- 私钥文件来自可信来源，并且已有受保护备份。

上面的 README 链接只要求完成 PIV 凭据准备。为本教程导入 X25519 key 不需要另外生成或替换
SSH `9a` key；如果 `9a` 已经有用途，不要修改它。

不要猜 PIN、私钥口令或 Management Key。错误 PIN 会消耗有限的重试次数。不要运行
`ykman piv reset`；导入一把 key 不需要重置 PIV 应用。

导入不会删除原始私钥文件。导入后的 key 会标记为 `IMPORTED`，也不能证明私钥只存在于
YubiKey 中。任何原始副本仍然可以绕过 YubiKey 使用。

## 1. 确认设备和空槽

只连接准备修改的那一把 YubiKey，然后读取它的十进制 serial：

```sh
ykman list --serials
```

输出必须只有一行十进制数字。没有输出或出现多行时先停止；不要凭设备插入顺序猜目标。
把下面以及本文余下命令中的 `<YubiKey serial>` 都换成这一行数字：

```sh
ykman --device '<YubiKey serial>' info
ykman --device '<YubiKey serial>' piv info
```

确认 key 对象不存在：

```sh
ykman --device '<YubiKey serial>' piv keys info 82
```

空槽在这里应返回失败，并报告没有 key。然后单独确认 certificate 对象也不存在：

```sh
ykman --device '<YubiKey serial>' piv certificates export 82 -
```

这条命令也应返回失败，并报告没有 certificate。如果它成功并输出证书，槽位就不是空的，即使
前一条命令没有显示 key 也必须停止。

如果 `82` 已经包含 key、证书或用途不明的对象，立即停止并选择另一个明确空闲的退休槽
`82` 到 `95`。不要用本教程覆盖它，也不要为了腾出槽位临时删除对象。尤其不要覆盖 SSH
通常使用的 `9a`。

如果同一设备和槽位以前已经配置给 YubiTouch，导入只会替换槽位中的 key，不会更新配置里
缓存的公钥。现有 profile 会出现公钥不匹配，旧 recipient 和旧密文仍绑定旧 key。此时不要继续
本教程，应先阅读 [更换硬件 key](age-reference.md#更换硬件-key)并完成旧密文迁移。

## 2. 检查私钥并保存预期公钥

下面所有 `/path/to/...` 都必须换成真实路径。不要把私钥内容、私钥口令或路径输出粘贴到
Issue 和日志中。

确认迁移文件只允许当前用户读取：

```sh
chmod 600 '/path/to/encrypted-x25519-pkcs8.pem'
```

先检查私钥能否被 OpenSSL 解析：

```sh
openssl pkey \
  -in '/path/to/encrypted-x25519-pkcs8.pem' \
  -check -noout
```

加密私钥会在终端中安全询问口令。不要使用 `-passin pass:...` 把口令放进命令行。成功时应
显示 `Key is valid`。

创建一个只保存公开验证材料的全新目录：

```sh
mkdir -p "$HOME/.config/yubitouch"
chmod 700 "$HOME/.config/yubitouch"

mkdir "$HOME/.config/yubitouch/x25519-import"
chmod 700 "$HOME/.config/yubitouch/x25519-import"
```

如果 `mkdir` 报告目录已存在，先停止并为本次导入选择另一个未使用的目录名；不要复用或清空
旧目录。下面的路径也要一起换成新名称。

从原私钥导出预期公钥：

```sh
openssl pkey \
  -in '/path/to/encrypted-x25519-pkcs8.pem' \
  -pubout \
  -out "$HOME/.config/yubitouch/x25519-import/x25519-public-before.pem"
```

同样让 OpenSSL 交互式询问口令。确认公开文件的类型：

```sh
openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-import/x25519-public-before.pem" \
  -text_pub -noout
```

第一行必须是 `X25519 Public-Key:`。如果显示其他算法，请停止。

如需记录公开指纹，可以运行：

```sh
openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-import/x25519-public-before.pem" \
  -outform DER |
  openssl dgst -sha256
```

## 3. 导入空闲槽位

再次确认命令中的槽位与第 1 节检查过的空槽一致。下面这条命令会写入 YubiKey；如果槽位并非
空闲，它会替换已有 key。

导入时，`ykman` 必须先在本机进程中解密私钥，再把 key 发送给 YubiKey。不要为这次操作启用
shell `set -x`、终端录制或 `ykman --log-level traffic`；traffic 日志可能记录包含私钥的完整
APDU。

```sh
ykman --device '<YubiKey serial>' piv keys import \
  --pin-policy ONCE \
  --touch-policy ALWAYS \
  82 '/path/to/encrypted-x25519-pkcs8.pem'
```

不要添加 `--password`、`--pin` 或 `--management-key` 参数；让 `ykman` 交互式读取所需凭据，
避免它们进入 shell history 和进程参数。使用受保护且要求触摸的 Management Key 时，按提示
输入 PIN 并触摸 YubiKey。

这里由 `ykman` 直接管理 PIV，不经过 YubiTouch daemon。因此不会显示 YubiTouch 的“age
解密”触摸提示；可能发生的触摸属于 Management Key 授权。

## 4. 核对策略和公钥

检查导入后的槽位元数据：

```sh
ykman --device '<YubiKey serial>' piv keys info 82
```

必须确认：

```text
Algorithm: X25519
Origin: IMPORTED
PIN required for use: ONCE
Touch required for use: ALWAYS
```

策略在导入时写入，不能原地改成另一组策略。任一字段不符合预期时，不要继续配置 YubiTouch。

从 YubiKey 导出对应的公开 key：

```sh
ykman --device '<YubiKey serial>' piv keys export \
  82 "$HOME/.config/yubitouch/x25519-import/x25519-public-after.pem"
```

不要为 X25519 添加 `--verify`。在支持槽位 public-key metadata 的固件上，`ykman` 会直接读取
metadata，不会通过一次私钥操作证明 key 可用；回退到 certificate 的路径才会尝试签名验证，
而 X25519 是 ECDH key，不能签名。下面的 DER 公钥比较加上后面的真实 ECDH 解密，才是本教程
使用的完整验证。

把导入前后的两个公钥规范化为 DER：

```sh
openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-import/x25519-public-before.pem" \
  -outform DER \
  -out "$HOME/.config/yubitouch/x25519-import/x25519-public-before.der"

openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-import/x25519-public-after.pem" \
  -outform DER \
  -out "$HOME/.config/yubitouch/x25519-import/x25519-public-after.der"
```

比较两个公开文件：

```sh
cmp "$HOME/.config/yubitouch/x25519-import/x25519-public-before.der" \
  "$HOME/.config/yubitouch/x25519-import/x25519-public-after.der"
```

`cmp` 没有输出并返回到提示符，表示导入后的公钥与原私钥完全匹配。输出不同或命令失败时，
不要生成 YubiTouch recipient，也不要处理原始私钥副本。

X25519 不能自签名。理论上，外部签发者可以为 X25519 subject public key 签发证书，但
YubiTouch 不需要证书，而是直接查找 YKCS11 的 public/private key 对象。除非另一个应用明确
要求，否则让这个槽位保持无证书状态，不要运行 `ykman piv certificates generate`；槽位中
遗留的不匹配证书还可能让其他工具导出错误公钥。

## 5. 配置 YubiTouch 并完成真实解密

导入和公钥比对成功后，继续
[age 使用教程的“配置硬件解密路径”](age-tutorial.md#2-配置硬件解密路径)。配置时使用刚才的
同一设备和槽位 `82`。

随后必须完成 age 教程中的以下步骤：

1. 生成新的 `age1yubitouch1...` recipient 和本机 identity；
2. 加密一份无敏感内容的测试文件；
3. 输入 PIN 或完成 1Password PIN 授权；
4. 在 YubiTouch 触摸提示出现后实际触摸设备；
5. 比较解密结果与原文件。

公钥比较只能证明槽位元数据与原 key 一致。真实 age 解密成功，才能确认 YKCS11 login、
PIN/touch policy 和 X25519 ECDH 整条路径可用。

不要把这把 hardware 私钥同时配置成 1Password recovery identity。两条路径必须使用独立 key，
YubiTouch 也会拒绝相同的 hardware 和 recovery 公钥。

## 6. 处理原始私钥副本

在完成真实解密和所需备份之前，保留原始私钥。验证成功后，根据你的恢复策略决定：

- 继续把加密 PKCS#8 文件作为受保护的离线备份；或
- 在确认其他恢复路径可靠后，手动移除迁移工作副本。

教程不会自动删除私钥。普通文件删除也不能保证从 APFS snapshot、备份或同步历史中抹除旧
副本。只要任何软件副本仍然存在，这把 key 就不具备“私钥只存在于 YubiKey”的安全属性。

公开验证材料不包含私钥；不再需要时可以删除
`$HOME/.config/yubitouch/x25519-import` 中的 `public-before`、`public-after` 和 DER 文件。

## 相关文档

- [使用 YubiTouch 保护 age 文件](age-tutorial.md)
- [在 YubiKey 内生成全新 X25519 私钥](piv-x25519-generate.md)
- [YubiTouch age 功能参考](age-reference.md)
- [项目安装与 PIV 基础配置](../README.md#安装与首次使用)
