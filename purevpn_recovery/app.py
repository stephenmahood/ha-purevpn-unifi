"""Home Assistant app: generate profiles only. Never changes UniFi VPN clients."""
import base64
import json
import logging
import os
from pathlib import Path
import signal
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat
from purevpn_client import PureVPN

DATA = Path("/data")
OPTIONS = DATA / "options.json"
LOG = logging.getLogger("purevpn_manager")
RUNNING = True


def shutdown(*_):
    global RUNNING
    RUNNING = False


def private_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as writer:
            writer.write(content)
        os.replace(temp, path)
        os.chmod(path, 0o600)
    finally:
        temp.unlink(missing_ok=True)


def keys_for(name):
    path = DATA / (name + "_keys.json")
    if path.exists():
        values = json.loads(path.read_text())
        return values["private"], values["public"]
    key = X25519PrivateKey.generate()
    private = base64.b64encode(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    public = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    private_write(path, json.dumps({"private": private, "public": public}))
    return private, public


def refresh(config):
    token_path = DATA / "token.txt"
    client = PureVPN()
    cached_token = token_path.read_text().strip() if token_path.exists() else None
    token = client.login(config["username"], config["password"], cached_token)
    private_write(token_path, token)
    for name in ("gb", "nl"):
        if not config.get(name + "_enabled", False):
            continue
        try:
            private, public = keys_for(name)
            country = config[name + "_country"].upper()
            city = int(config[name + "_city_id"])
            profile = client.generate(country, city, private, public)
            private_write(DATA / "profiles" / (name + ".conf"), profile)
            LOG.info("%s profile generated privately (country=%s)", name.upper(), country)
        except Exception as exc:
            LOG.error("%s profile generation failed (%s)", name.upper(), type(exc).__name__)


def main():
    config = json.loads(OPTIONS.read_text())
    logging.basicConfig(level=getattr(logging, config.get("log_level", "info").upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s")
    if not config.get("username") or not config.get("password"):
        LOG.warning("Set PureVPN credentials in the app Configuration tab")
        return
    LOG.info("PureVPN WireGuard Manager started; auto_generate=%s; no UniFi writes",
             config.get("auto_generate", False))
    if not config.get("auto_generate", False):
        LOG.info("Safe mode: PureVPN API access disabled")
        return
    interval = max(5, int(config["refresh_minutes"])) * 60
    while RUNNING:
        try:
            refresh(config)
        except Exception as exc:
            LOG.error("PureVPN refresh failed (%s)", type(exc).__name__)
        for _ in range(interval):
            if not RUNNING:
                break
            time.sleep(1)
    LOG.info("Stopped")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    main()
