# YubiTouch @VERSION@

Commit: `@COMMIT@`

Platform: macOS 13+, `@ARCH@`

## Installation

Install Homebrew OpenSSH, yubico-piv-tool, and ykman. Move `YubiTouch.app` to `/Applications`,
link its `Contents/MacOS/yubitouch` executable into `PATH`, then follow the README to configure the
PIV 9A public key and register the current-user LaunchAgent.

YubiTouch uses `IdentityAgent` and does not require `Match exec`, an SSH wrapper, or Agent Forwarding.

## Security

PIN values are not stored in configuration, normal environment variables, logs, state, or release
artifacts. YubiTouch is an independent open-source project and is not affiliated with or endorsed by
Yubico.

## Known Limitations

Review `docs/verification.md` and the v0.1 QA Issue before release. Real YubiKey signing, 1Password
Desktop App Integration, LaunchAgent KeepAlive, supported OpenSSH/yubico-piv-tool versions,
DebianForm, full-screen UI, Developer ID signing, and notarization require recorded macOS validation.
