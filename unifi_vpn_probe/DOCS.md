# UniFi outbound VPN status probe
This is a one-shot **read-only** probe for confirming whether the UDM-SE's local
Network API exposes individual PureVPN WireGuard tunnel states.

Configure a dedicated read-only UniFi account. Use HTTPS and enable certificate
verification when your gateway presents a trusted certificate. If your gateway
uses its default self-signed certificate, either install its CA or temporarily
disable verification for this local diagnostic only.

Run the app, examine the Logs tab, and share only the redacted status output.
The app never changes VPN settings, never reports server endpoints, private keys
or tunnel addresses and does not yet create status entities or notifications.

Known limitation: Network configuration can report enablement but not live
connected status; gateway-wide VPN health is not reliable per tunnel. If the
probe finds no suitable live status, the next stage must examine UniFi UI's
read-only status source or SSH/WireGuard handshakes before creating alerts.
