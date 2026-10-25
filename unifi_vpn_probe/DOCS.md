# UniFi Outbound VPN Status Probe v0.2.0

Uses an API key from **UniFi Network → Settings → Integrations**.
Enter the gateway HTTPS URL and the key in the Home Assistant app's configuration.
The API key is masked in the settings and is never logged.

This one-shot diagnostic checks the official Network Integration API's `/sites`
endpoint, to confirm the key and routing work. The official API may **not**
expose real-time outbound WireGuard tunnel state. No notification automation
or tunnel status entities are created in this version.

The old username/password login and legacy Network API diagnostic calls have
been removed. The official API key is not assumed to work against the legacy
`/proxy/network/api/s/default/rest/networkconf` endpoint.

After running, check the app Logs tab and share the HTTP status output.
It never changes your VPN configuration.
