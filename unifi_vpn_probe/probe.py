"""Read-only official UniFi Network Integration API probe; no VPN changes."""
import json
import logging
from pathlib import Path
from urllib.parse import urlparse

import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("unifi_vpn_probe")
cfg = json.loads(Path("/data/options.json").read_text())
base = cfg["controller_url"].rstrip("/")
parsed = urlparse(base)
if parsed.scheme != "https" or not parsed.hostname:
    raise ValueError("Controller URL must use HTTPS")
key = cfg.get("api_key", "").strip()
if not key:
    raise ValueError("Configure a UniFi Network Integration API key")
session = requests.Session()
session.verify = cfg.get("verify_ssl", True)
session.headers.update({"Accept": "application/json", "X-API-Key": key})
# Only official integration endpoints are used in API-key mode.
# Legacy /proxy/network/api/... endpoints require different authentication
# and must not be assumed to accept the new integration API key.
candidate_bases = (
    "/proxy/network/integration/v1",
    "/integration/v1",
)
try:
    for prefix in candidate_bases:
        try:
            response = session.get(base + prefix + "/sites", timeout=15)
            log.info("Official Network API (%s) sites HTTP %s",
                     prefix, response.status_code)
            if response.status_code == 200:
                payload = response.json()
                # Site metadata can be sensitive. Record only number of sites.
                sites = payload.get("data", []) if isinstance(payload, dict) else []
                log.info("Official API authenticated; listed %s site records",
                         len(sites) if isinstance(sites, list) else "unknown")
                # Check candidate path separately; unsupported paths return 404.
                if isinstance(sites, list):
                    for site in sites[:3]:
                        sid = site.get("id")
                        if not isinstance(sid, str) or not sid:
                            continue
                        path = prefix + "/sites/" + sid + "/vpn-clients"
                        response_vpn = session.get(base + path, timeout=15)
                        log.info("VPN clients listing HTTP %s", response_vpn.status_code)
                        if response_vpn.status_code != 200:
                            continue
                        listing = response_vpn.json()
                        records = listing.get("data", []) if isinstance(listing, dict) else []
                        log.info("VPN client records returned: %s", len(records) if isinstance(records, list) else "unknown")
                        if isinstance(records, list):
                            for client in records:
                                if not isinstance(client, dict):
                                    continue
                                name = str(client.get("name", "")).lower()
                                if "purevpn" not in name:
                                    continue
                                region = "GB" if "gb" in name else "NL" if "nl" in name else "unclassified"
                                # Print only known harmless connection-status fields.
                                permitted = ("status", "connectionStatus", "state", "connected", "isConnected")
                                values = {k: client[k] for k in permitted if k in client and isinstance(client[k], (str, bool))}
                                log.info("PureVPN %s live_status=%s", region, values or "not exposed")
                break
            if response.status_code in (401, 403):
                log.warning("API key rejected or insufficient access")
                break
        except (requests.RequestException, ValueError, TypeError) as exc:
            log.warning("Official API probe failed (%s)", type(exc).__name__)
    else:
        log.warning("No supported local Network Integration API route responded")
finally:
    pass
# Internal UniFi Network v2 route observed in the controller UI.
# This endpoint is undocumented and may reject Integration API keys.
try:
    response = session.get(
        base + "/proxy/network/v2/api/site/default/vpn/connections", timeout=15
    )
    log.info("Internal VPN connections endpoint HTTP %s", response.status_code)
    if response.status_code == 200:
        payload = response.json()
        entries = payload.get("data", []) if isinstance(payload, dict) else payload
        if not isinstance(entries, list):
            log.info("Internal VPN response shape=%s; contents suppressed", type(entries).__name__)
        else:
            log.info("Internal VPN connection records=%d", len(entries))
            # Whitelist innocuous fields; never log raw response or keys.
            for item in entries:
                if not isinstance(item, dict):
                    continue
                name = str(item.get("name", ""))
                if "purevpn" not in name.lower():
                    continue
                region = "GB" if "gb" in name.lower() else "NL" if "nl" in name.lower() else "Other"
                fields = ("status", "state", "connection_status", "connectionStatus",
                          "connected", "isConnected")
                safe = {k: v for k in fields if isinstance((v := item.get(k)), (bool, str, int))}
                log.info("Internal PureVPN %s connection state=%s", region, safe or "no recognised fields")
    elif response.status_code in (401, 403):
        log.warning("Internal VPN route requires controller session authentication; integration API key insufficient")
    elif response.status_code == 404:
        log.warning("Internal VPN route not available on this controller")
except (requests.RequestException, ValueError, TypeError) as exc:
    log.warning("Internal VPN endpoint probe failed (%s)", type(exc).__name__)
session.close()
log.info("Read-only probe complete; no VPN settings changed")
