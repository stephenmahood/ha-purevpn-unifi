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
                log.info("VPN client status via official API: not yet verified")
                break
            if response.status_code in (401, 403):
                log.warning("API key rejected or insufficient access")
                break
        except (requests.RequestException, ValueError, TypeError) as exc:
            log.warning("Official API probe failed (%s)", type(exc).__name__)
    else:
        log.warning("No supported local Network Integration API route responded")
finally:
    session.close()
log.info("Read-only probe complete; no VPN settings changed")
