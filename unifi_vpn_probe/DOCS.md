# UniFi PureVPN status monitor v0.3.0

Uses the local UniFi controller's read-only API with an X-API-Key and joins:
- `GET /proxy/network/api/s/default/rest/networkconf` (configured VPN names, enabled state, network IDs)
- `GET /proxy/network/v2/api/site/default/vpn/connections` (live client status).

No raw configuration or private keys are logged or saved.

## Configure
- `controller_url`: HTTPS address of your gateway
- `api_key`: Network API key
- `verify_ssl`: enable with a trusted certificate
- `monitor_enabled`: **false** by default; turn on for continuous polling
- `poll_seconds`: 30 (15–300)
- `failure_seconds`: 120 (60–3600)
- `notify_service`: `mobile_app_stephens_iphone`

When monitoring is enabled, start the add-on and enable **Start on boot** in the HA app UI for persistent operation. Uses HA Supervisor's internal Core API with its addon token to call the configured mobile notification service.

## Alert behavior
- Enabled `CONNECTED`: healthy
- Disabled: no alert
- Enabled `DISCONNECTED`, `CONNECTING`, `NOT_ESTABLISHED`: alert after threshold
- Enabled `NOT_LISTED`: alert as **needs manual attention** after threshold. This means the enabled client is missing from the live listing, not necessarily definitely disconnected.
- `UNKNOWN` or endpoint errors: no disconnection inferred.
- One notification per failure event; a recovery notification on return to `CONNECTED` after a successful alert.

For safety `monitor_enabled=false` performs a single read-only status snapshot without sending alerts under normal circumstances. No VPN configuration is changed. Test notifications on the phone before relying on this as the only detection mechanism. The internal API is undocumented and may change after UniFi updates.
