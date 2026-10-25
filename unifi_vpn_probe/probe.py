"""Read-only UniFi VPN monitor with optional Home Assistant notifications.

Never logs, stores or modifies WireGuard keys or full network configurations.
"""
import json
import logging
import time
from pathlib import Path
from urllib.parse import urlparse
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("unifi_vpn_monitor")
cfg = json.loads(Path("/data/options.json").read_text())
base = cfg["controller_url"].rstrip("/")
parsed = urlparse(base)
if parsed.scheme != "https" or not parsed.hostname:
    raise ValueError("HTTPS controller URL required")
api_key = cfg.get("api_key", "").strip()
if not api_key:
    raise ValueError("UniFi API key missing")
session = requests.Session()
session.verify = cfg.get("verify_ssl", True)
session.headers.update({"Accept": "application/json", "X-API-Key": api_key})
config_url = base + "/proxy/network/api/s/default/rest/networkconf"
connections_url = base + "/proxy/network/v2/api/site/default/vpn/connections"
interval = max(15, int(cfg.get("poll_seconds", 30)))
failure_after = max(60, int(cfg.get("failure_seconds", 120)))
monitor = bool(cfg.get("monitor_enabled", False))
notify_service = cfg.get("notify_service", "mobile_app_stephens_iphone")
if not notify_service.startswith("mobile_app_") or not all(
    c.isalnum() or c == "_" for c in notify_service
):
    raise ValueError("notify_service must be a Home Assistant mobile_app notify service")
status = {region: {"since": None, "alerted": False} for region in ("GB", "NL")}
# No key is ever included in exception messages.
def get_json(url):
    r = session.get(url, timeout=15)
    if r.status_code != 200:
        log.warning("UniFi endpoint HTTP %d", r.status_code)
        return None
    return r.json()

def read_states():
    config = get_json(config_url)
    live = get_json(connections_url)
    if not isinstance(config, dict) or not isinstance(live, dict):
        return None
    networks = config.get("data")
    connections = live.get("connections")
    if not isinstance(networks, list) or not isinstance(connections, list):
        log.warning("Unexpected UniFi response schema")
        return None
    active = {}
    for connection in connections:
        if isinstance(connection, dict) and connection.get("type") == "wireguard-client":
            active[connection.get("network_id")] = connection.get("status")
    result = {}
    for row in networks:
        if not isinstance(row, dict) or row.get("purpose") != "vpn-client":
            continue
        name = str(row.get("name", "")).strip().lower()
        region = {"purevpn - gb": "GB", "purevpn - nl": "NL"}.get(name)
        if not region:
            continue
        if row.get("enabled") is not True:
            result[region] = "DISABLED"
        elif row.get("_id") not in active:
            result[region] = "NOT_LISTED"
        else:
            state = active[row["_id"]]
            result[region] = state if state in (
                "CONNECTED", "CONNECTING", "DISCONNECTED", "NOT_ESTABLISHED"
            ) else "UNKNOWN"
    return result

def send_notification(region, recovered, detail):
    message = (f"PureVPN {region} has recovered and is CONNECTED." if recovered
               else f"PureVPN {region} needs manual attention. UniFi reports {detail} "
                    f"for at least {failure_after} seconds.")
    token = __import__("os").environ.get("SUPERVISOR_TOKEN")
    if not token:
        log.error("Notification unavailable: SUPERVISOR_TOKEN missing")
        return False
    try:
        r = requests.post(
            "http://supervisor/core/api/services/notify/" + notify_service,
            headers={"Authorization": "Bearer " + token},
            json={"title": f"PureVPN {region} " + ("reconnected" if recovered else "connection alert"),
                  "message": message},
            timeout=15,
        )
        if r.status_code not in (200, 201):
            log.warning("Home Assistant notification returned HTTP %d", r.status_code)
            return False
        return True
    except requests.RequestException:
        log.warning("Home Assistant notification could not be delivered")
        return False

log.info("UniFi PureVPN status monitor starting; monitoring=%s", monitor)
while True:
    try:
        current = read_states()
        now = time.monotonic()
        if current is None:
            log.warning("UniFi API unavailable; no tunnel state inferred")
        else:
            for region in ("GB", "NL"):
                state = current.get(region, "UNKNOWN")
                log.info("PureVPN %s status=%s", region, state)
                item = status[region]
                if state == "CONNECTED":
                    if item["alerted"] and send_notification(region, True, state):
                        item["alerted"] = False
                    item["since"] = None
                elif state == "DISABLED":
                    item["since"] = None
                    item["alerted"] = False
                elif state in ("DISCONNECTED", "NOT_ESTABLISHED", "CONNECTING", "NOT_LISTED"):
                    # NOT_LISTED means an enabled tunnel is absent from UniFi's
                    # live connection list, not a confirmed disconnected state.
                    if item["since"] is None:
                        item["since"] = now
                    if not item["alerted"] and now - item["since"] >= failure_after:
                        if send_notification(region, False, state):
                            item["alerted"] = True
                else:
                    # Unknown status is not treated as a disconnection.
                    item["since"] = None
    except (requests.RequestException, ValueError, TypeError, KeyError):
        log.warning("UniFi status polling failed; no disconnection inferred")
    if not monitor:
        break
    time.sleep(interval)
session.close()
log.info("VPN monitor stopped")
