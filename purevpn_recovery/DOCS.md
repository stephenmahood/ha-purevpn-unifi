# PureVPN WireGuard Manager — v0.1.0 preview

Configure your PureVPN email and password, GB/NL profiles, optional city IDs and refresh interval in the Configuration tab.

Startup with `auto_generate: false` verifies app startup without PureVPN API access. When enabled, the app authenticates and generates or refreshes the enabled profiles at the configured interval, starting immediately.

Generated profiles are stored securely under `/data/profiles`; separate key pairs for GB and NL are kept under `/data`. App backups contain secrets.

The app emits operational logs but never logs tokens, credentials, private keys or full profiles. If PureVPN blocks automated authentication with CAPTCHA/MFA, profile generation may fail.

## Limitations
- Unofficial and untested PureVPN customer portal API.
- No UniFi client update, connection monitoring, Home Assistant status entities or notifications in this release.
- No remote control endpoint; startup and periodic refresh only.
- PureVPN profile lifetime and refresh effects have not been verified live.
