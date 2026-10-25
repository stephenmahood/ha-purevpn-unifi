# PureVPN WireGuard Manager for Home Assistant

**Experimental v0.1.0:** Generates and periodically refreshes PureVPN WireGuard profiles for GB and NL using unofficial customer portal endpoints. **This version does not change UniFi VPN clients or monitor VPN connection status.**

## Install
Open Home Assistant **Settings → Apps → App Store → ⋮ → Repositories** and add:

https://github.com/stephenmahood/ha-purevpn-unifi

Install **PureVPN WireGuard Manager**, configure your account credentials and region settings, then start the app. API generation is disabled by default; enable `auto_generate` only when ready to test.

Logs appear in the app Logs tab. Keys, tokens and generated WireGuard profiles are saved within the add-on's private `/data` directory and must never be shared.

**Security:** This uses an unofficial API and has not been tested with a live PureVPN account. It can stop working, trigger rate limits, CAPTCHA/MFA or account restrictions. Never paste VPN private keys or account credentials into GitHub issues.

Inspired by https://github.com/TwoOnefour/purevpn-wg-auto-conf. Not affiliated with PureVPN or Ubiquiti.
