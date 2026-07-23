# 在 YubiKey 内生成用于 YubiTouch age 的 X25519 私钥

本教程在 YubiKey 内部生成一把全新的 PIV X25519 私钥，供 YubiTouch age hardware 路径
使用。示例使用退休槽 `82`，并设置 YubiTouch 要求的 PIN `ONCE`、touch `ALWAYS` 策略。

私钥由 YubiKey 生成，不能通过 PIV 接口导出；`ykman` 只把公钥写入本机文件。这适合创建
全新的 hardware key。如果必须保留一把已有的 PKCS#8 X25519 私钥，请改用
[导入已有 X25519 私钥](piv-x25519-import.md)。

这是有覆盖风险的 PIV 管理操作。请完整读完“开始前”和“确认空槽”，再执行生成命令。

## 教程范围

本教程创建的是 YubiTouch hardware key，不是 `age-keygen` 创建的原生 age identity。完成
YubiTouch 配置后会得到新的 `age1yubitouch1...` recipient；它不能自动解开已有的原生 age
`X25519` stanza，也不能解开绑定到另一把 YubiTouch key 的旧密文。

如果同一 serial 和 slot 已经配置给 YubiTouch，重新生成 key 会让缓存公钥、recipient 和旧密文
仍然绑定旧 key。此时不要按本教程覆盖槽位，应先阅读
[更换硬件 key](age-reference.md#更换硬件-key)并完成旧密文迁移。

## 开始前

确认以下条件：

- 使用固件 5.7 或更高版本、支持 PIV X25519 的非 FIPS YubiKey；当前真实验收设备固件为
  5.7.4；
- 已安装 `ykman` 5.9.2、OpenSSL 3 和 YKCS11 2.7.3；
- 已按 [README 的 PIV 准备步骤](../README.md#2-配置-yubikey-piv-9a)修改默认 PIN、PUK 和
  Management Key；
- 只连接准备修改的那一把 YubiKey；
- 有另一种可靠的登录方式，不依赖准备修改的槽位；
- 已经决定使用 hardware-only，或计划在处理真实数据前配置独立的 1Password recovery key。

上面的 README 链接只要求完成 PIV 凭据准备。为本教程生成 X25519 key 不需要另外生成或替换
SSH `9a` key；如果 `9a` 已经有用途，不要修改它。

FIPS 型号不支持这条 PIV X25519 生成路径；不要临时改用另一种算法，因为 YubiTouch age
hardware profile 只接受 X25519。

不要猜 PIN 或 Management Key。错误 PIN 会消耗有限的重试次数。不要运行 `ykman piv reset`；
生成一把 key 不需要重置 PIV 应用。

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

## 2. 准备公钥输出目录

创建一个只保存本次公开材料的全新目录：

```sh
mkdir -p "$HOME/.config/yubitouch"
chmod 700 "$HOME/.config/yubitouch"

mkdir "$HOME/.config/yubitouch/x25519-generated-82"
chmod 700 "$HOME/.config/yubitouch/x25519-generated-82"
```

如果第二个 `mkdir` 报告目录已存在，先停止并选择另一个未使用的目录名；不要复用或清空旧
目录。下面的路径也要一起换成新名称。

这个目录只会保存公钥。公钥可以分发，也不能用于解密；它不是硬件私钥的备份。

## 3. 在 YubiKey 内生成 key

再次确认命令中的 serial 和 slot 与第 1 节检查的目标完全相同。下面这条命令是本教程唯一写入
YubiKey 的步骤；如果槽位并非空闲，它会替换已有 key。

```sh
ykman --device '<YubiKey serial>' piv keys generate \
  --algorithm X25519 \
  --pin-policy ONCE \
  --touch-policy ALWAYS \
  82 - \
  > "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-generated.pem"
```

这里让 `ykman` 把 PEM 公钥写到标准输出，再由 shell 重定向到文件。shell 会在启动 `ykman`
之前打开目标文件；如果目录或权限错误，YubiKey 不会被修改。不要在这里添加 `tee`。

不要添加 `--pin` 或 `--management-key` 参数；让 `ykman` 交互式读取所需凭据，避免它们进入
shell history 和进程参数。不要为这次操作启用 shell `set -x`、终端录制或
`ykman --log-level traffic`；使用受 PIN 保护的 Management Key 时，traffic 日志可能记录 PIN。

使用受保护且要求触摸的 Management Key 时，按 `ykman` 提示输入 PIN 并触摸 YubiKey。这是
PIV 管理授权，不是新 X25519 key 的解密操作，因此不会显示 YubiTouch 的“age 解密”触摸提示。
`--touch-policy ALWAYS` 会在以后每次使用这把私钥执行 ECDH 时强制触摸。

成功时，命令正常返回，并把 PEM 公钥写入指定文件。因为公钥经过标准输出重定向，`ykman`
不会再把成功说明混入 PEM。私钥不会写入该文件，也不能通过后续的 public-key export 命令
导出。

如果命令失败、中断或结果不确定，不要直接重跑。生成可能已经在设备内完成，只是公钥写入
失败；空文件也不能证明槽位仍为空。先执行下一节的 `keys info`：如果槽位中已经有 key，继续
核对并导出公钥；只有 key 和 certificate 检查都仍明确为空时，才重新考虑执行生成命令。

## 4. 核对策略和公钥

检查槽位元数据：

```sh
ykman --device '<YubiKey serial>' piv keys info 82
```

必须确认：

```text
Algorithm: X25519
Origin: GENERATED
PIN required for use: ONCE
Touch required for use: ALWAYS
```

`Origin: GENERATED` 表示 YubiKey metadata 报告这把 key 是在设备内生成的，不应把这个字段
单独描述成密码学 attestation。策略在生成时写入，不能原地改成另一组策略。任一字段不符合
预期时，不要继续配置 YubiTouch，也不要直接重新生成。

生成操作不会创建证书。再次确认槽位仍没有 certificate：

```sh
ykman --device '<YubiKey serial>' piv certificates export 82 -
```

这条命令应返回失败并报告没有 certificate。

确认生成命令写出的文件是 X25519 公钥：

```sh
openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-generated.pem" \
  -text_pub -noout
```

第一行必须是 `X25519 Public-Key:`。如果生成命令没有成功写出这个文件，先从槽位重新导出
公钥：

```sh
ykman --device '<YubiKey serial>' piv keys export \
  82 "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-exported.pem"
```

正常生成时也必须执行这条 export。确认导出的文件同样是 X25519 公钥：

```sh
openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-exported.pem" \
  -text_pub -noout
```

如果 generated PEM 无效，以新导出的 PEM 作为公开核对材料，跳过下面的双文件 DER 比较，并
在查明原命令失败阶段之前不要处理真实数据。如果两个 PEM 都有效，再把它们分别规范化为 DER：

```sh
openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-generated.pem" \
  -outform DER \
  -out "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-generated.der"

openssl pkey \
  -pubin \
  -in "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-exported.pem" \
  -outform DER \
  -out "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-exported.der"
```

比较两个公开文件：

```sh
cmp "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-generated.der" \
  "$HOME/.config/yubitouch/x25519-generated-82/x25519-public-exported.der"
```

`cmp` 没有输出并返回到提示符，表示两次得到的是同一把公钥。输出不同或命令失败时，不要
配置 YubiTouch，也不要处理真实数据。

不要为 export 添加 `--verify`：在支持 slot public-key metadata 的固件上，它不会执行私钥操作；
回退到 certificate 的路径才会尝试签名，而 X25519 不能签名。后面的真实 ECDH 解密才是私钥
可用性验证。

X25519 不能自签名。YubiTouch 直接查找 YKCS11 的 public/private key 对象，不需要证书。
让这个槽位保持无证书状态，不要运行 `ykman piv certificates generate`。

## 5. 配置 YubiTouch 并完成真实解密

元数据和公钥检查通过后，继续
[age 使用教程的“配置硬件解密路径”](age-tutorial.md#2-配置硬件解密路径)。配置时使用刚才的
同一 serial 和 slot `82`。

随后必须完成 age 教程中的以下步骤：

1. 生成新的 `age1yubitouch1...` recipient 和本机 identity；
2. 加密一份无敏感内容的测试文件；
3. 输入 PIN 或完成 1Password PIN 授权；
4. 在 YubiTouch 触摸提示出现后实际触摸设备；
5. 比较解密结果与原文件。

公钥和 metadata 只能说明槽位看起来配置正确。真实 age 解密成功，才能确认 YKCS11 login、
PIN/touch policy 和 X25519 ECDH 整条路径可用。

## 6. 决定恢复方式

设备内生成的私钥不能复制出来。槽位被删除或覆盖、PIV 应用被重置，或者 YubiKey 丢失或损坏
后，没有独立 recovery stanza 的密文将无法恢复。公钥 PEM、YubiTouch recipient 和 identity
都不是私钥备份。

需要 1Password recovery 时，应在加密真实数据之前按
[age 教程的 recovery 步骤](age-tutorial.md#8-可选增加-1password-recovery)完成配置和缺卡恢复
测试。recovery 必须使用另一把独立的 X25519 key，不能声称是 YubiKey 私钥的副本。

recovery 只会写入使用新组合 recipient 加密的文件。以后再启用 recovery，不能为已经存在的
hardware-only 密文补写 recovery stanza。

公开 PEM 可以作为设备和槽位的核对材料保存或分发。删除它不会删除 YubiKey 中的私钥，但也
不会提高私钥安全性。

## 相关文档

- [使用 YubiTouch 保护 age 文件](age-tutorial.md)
- [导入已有 X25519 私钥](piv-x25519-import.md)
- [YubiTouch age 功能参考](age-reference.md)
- [项目安装与 PIV 基础配置](../README.md#安装与首次使用)
