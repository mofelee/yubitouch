# YubiTouch @VERSION@

Commit: `@COMMIT@`

Platform: macOS 13+, `@ARCH@`

## Installation

Install Homebrew OpenSSH, yubico-piv-tool, and ykman. Move `YubiTouch.app` to `/Applications`,
link its `Contents/MacOS/yubitouch` executable into `PATH`, then follow the README to configure the
PIV 9A public key and register the current-user LaunchAgent. age users must also install age and link
the exact plugin entry point:

```sh
mkdir -p "$HOME/.local/bin"
ln -sfn /Applications/YubiTouch.app/Contents/MacOS/yubitouch \
  "$HOME/.local/bin/yubitouch"
ln -sfn /Applications/YubiTouch.app/Contents/MacOS/age-plugin-yubitouch \
  "$HOME/.local/bin/age-plugin-yubitouch"
```

The release also contains standalone `yubitouch-@VERSION@-darwin-@ARCH@` and
`age-plugin-yubitouch-@VERSION@-darwin-@ARCH@` artifacts; install the plugin under the exact name
`age-plugin-yubitouch`. Both standalone executables are signed independently with Hardened Runtime
instead of retaining the App bundle's `Info.plist` binding. The App and all standalone artifacts are
covered by `SHA256SUMS`.

YubiTouch uses `IdentityAgent` and does not require `Match exec`, an SSH wrapper, or Agent Forwarding.

## age Plugin

This release adds the versioned `age1yubitouch1...` recipient and
`AGE-PLUGIN-YUBITOUCH-1...` identity formats. It uses an existing YubiKey PIV X25519 key as the
primary decryption path and supports at most one independent native age X25519 recovery identity in
1Password. It does not generate, import, overwrite, delete, or synchronize PIV keys.

Configure age only through an explicit `yubitouch configure` invocation. The six supported inputs
are `YUBITOUCH_AGE_SERIAL`, `YUBITOUCH_AGE_SLOT`, `YUBITOUCH_AGE_ALGORITHM`,
`YUBITOUCH_AGE_RECOVERY_PROVIDER`, `YUBITOUCH_AGE_RECOVERY_IDENTITY_REF`, and
`YUBITOUCH_AGE_RECOVERY_RECIPIENT`. They are merged into the private configuration file; the daemon
does not use interactive shell variables as per-request overrides. Recovery private-key variables,
including `YUBITOUCH_AGE_RECOVERY_IDENTITY`, `YUBITOUCH_AGE_RECOVERY_PRIVATE_KEY`, and
`YUBITOUCH_AGE_RECOVERY_SECRET`, are rejected.

After configuration, generate the two one-line files and use normal age commands:

```sh
yubitouch age recipient > recipient.txt
yubitouch age identity > identity.txt
yubitouch reload
age -R recipient.txt -o secret.txt.age secret.txt
age -d -i identity.txt -o secret.txt secret.txt.age
```

Encryption uses only public recipient material and does not contact the daemon, YubiKey, or
1Password. Decryption uses the private age socket. A connected target always selects PIV X25519.
The isolated helper completes the configured PIN provider and YKCS11 login first. The daemon shows
the native touch prompt only after both succeed and before allowing hardware ECDH to continue.
Only two consecutive successful target probes returning `not_detected` can start one recovery
helper. A different device, target/key mismatch, unknown probe state, PIN/provider failure, user
cancel, touch timeout, or YKCS11/ECDH/KDF/AEAD failure fails closed with no recovery call. A request
that has selected hardware never switches to recovery.

The v1 format uses independent ephemeral X25519 wraps, HKDF-SHA256 with domain-separated salt/info
that binds the ephemeral and recipient public keys, and ChaCha20-Poly1305 authenticated wrapping of
the 16-byte age file key. AEAD associated data also binds the path, profile, key IDs, and public keys.
Strict parsing rejects unknown versions/algorithms/paths, malformed data, duplicate hardware or
recovery stanzas, a missing hardware stanza, non-canonical or low-order keys, and invalid hardware
IDs/bindings. Connected hardware remains usable for ciphertext created before recovery is enabled,
disabled, or rotated; only a missing-device fallback requires the stanza recovery ID to match the
current configuration. Protocol and plugin automation target age v1.3.1; this format is unrelated
to and incompatible with `age-plugin-yubikey`.

## Security

PIN values are not stored in configuration, normal environment variables, logs, state, or release
artifacts. The recovery helper reads one configured identity, verifies its public recipient, unwraps
inside a one-shot process, and returns only the age file key. Core dumps are disabled and mutable
buffers are cleared where possible. The 1Password SDK returns secrets as immutable Go strings that
cannot be reliably zeroed, so short helper lifetime and process exit are the primary isolation
boundary and do not provide hardware non-exportability.

On macOS, private helpers require the same runtime-hardened executable identity as their direct
parent and reject DYLD-environment or debugging entitlements. A dedicated lifetime pipe kills the
helper process group if the daemon exits unexpectedly. Initial age public-key cache writes are
serialized with configuration updates, merge only the cache into the latest configuration, and
fail without output if the configured hardware target changed during the read.

Enabling recovery lowers the security of the whole ciphertext: the hardware and recovery paths are
an OR relationship, and either private key can decrypt independently. Do not use the upstream
`AGEDEBUG=plugin` setting with real data; age debug output can expose plugin protocol contents and
file-key material outside YubiTouch's redacted logging boundary.

YubiTouch is an independent open-source project and is not affiliated with or endorsed by Yubico.

## Known Limitations

Review `docs/verification.md` and the v0.1 QA Issue before release. Real YubiKey signing, 1Password
Desktop App Integration, LaunchAgent KeepAlive, supported OpenSSH/yubico-piv-tool versions,
DebianForm, full-screen UI, Developer ID signing, and notarization require recorded macOS validation.

The age PIV ECDH prerequisite and the complete signed-source-build hardware `age -R`/`age -d -i`
flow are verified on arm64 macOS with YubiKey firmware 5.7.4, YKCS11 2.7.3, and age v1.3.1.
Two consecutive hardware decryptions succeeded and matched the plaintext; while the 1Password PIN
provider authorization was deliberately left pending, the YubiTouch touch UI remained hidden and
appeared only after authorization completed. Real recovery success, authorization rejection,
timeout, helper crash, and identity-mismatch paths remain pending and must not be inferred from unit
tests.
Wrong-PIN testing consumes device retries and should only be performed on a prepared test device
with a confirmed recovery plan.

Replacing the X25519 key in the same configured serial and slot does not automatically invalidate
the cached `age.public_key` in this release. Stop the daemon, remove only that JSON field, regenerate
the recipient and identity with the target device inserted, replace every distributed copy of the
old recipient, and reload. Ciphertext created for an unavailable old key is unrecoverable unless it
also contains a usable recovery stanza.
