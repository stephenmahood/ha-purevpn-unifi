"""Read-only diagnostics. Never prints keys, endpoints, IPs or credentials."""
import json
import logging
import re
from pathlib import Path
from urllib.parse import urlparse
import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("unifi_vpn_probe")
cfg = json.loads(Path("/data/options.json").read_text())
url = cfg["controller_url"].rstrip("/")
parsed = urlparse(url)
if parsed.scheme != "https" or not parsed.hostname:
    raise ValueError("Controller URL must use HTTPS")
if not cfg["username"] or not cfg["password"]:
    raise ValueError("Configure a dedicated read-only UniFi account")
site = cfg.get("site", "default")
if not re.fullmatch(r"[a-zA-Z0-9_-]+", site):
    raise ValueError("Invalid site reference")
session = requests.Session()
session.verify = cfg.get("verify_ssl", True)
session.headers.update({"Accept": "application/json"})
try:
    auth = session.post(url + "/api/auth/login",
                        json={"username":cfg["username"], "password":cfg["password"]},
                        timeout=15)
    log.info("Controller authentication HTTP %s", auth.status_code)
    auth.raise_for_status()
    # Query only known read-only endpoints. Raw responses are deliberately
    # discarded; they can contain WireGuard private keys and credentials.
    endpoints = {
        "vpn_config": "/proxy/network/api/s/" + site + "/rest/networkconf",
        "vpn_health": "/proxy/network/api/s/" + site + "/stat/health",
        "gateway": "/proxy/network/api/s/" + site + "/stat/device",
    }
    for label, path in endpoints.items():
        try:
            result = session.get(url + path, timeout=15)
            log.info("%s HTTP %s", label, result.status_code)
            if result.status_code != 200:
                continue
            data = result.json().get("data", [])
            if label == "vpn_config":
                matched = [x for x in data if x.get("purpose") == "vpn-client" and
                           "purevpn" in str(x.get("name", "")).lower()]
                for item in matched:
                    # Whitelist possible status fields only. Do not reveal other fields.
                    fields = ("state", "status", "connection_status", "connected",
                              "last_handshake", "last_handshake_time")
                    values = {k: str(item[k])[:80] for k in fields if k in item}
                    log.info("PureVPN client %s: status_fields=%s",
                             "GB" if "gb" in item.get("name","").lower() else
                             "NL" if "nl" in item.get("name","").lower() else "Other",
                             values or "none")
                log.info("Matched PureVPN client configurations: %d", len(matched))
            elif label == "vpn_health":
                for item in data:
                    if item.get("subsystem") == "vpn":
                        log.info("Site VPN health status=%s (not per-client)",
                                 str(item.get("status","unknown"))[:50])
            elif label == "gateway":
                log.info("Gateway data received: %s records (raw content suppressed)", len(data))
        except Exception as exc:
            log.warning("%s inspection failed: %s", label, type(exc).__name__)
finally:
    try:
        session.post(url + "/api/auth/logout", timeout=10)
    except Exception:
        pass
log.info("Read-only probe complete. No VPN settings changed.")
