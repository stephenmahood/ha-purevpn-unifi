"""Unofficial PureVPN WireGuard customer portal API adapter.
Derived from the public API flow documented by TwoOnefour/purevpn-wg-auto-conf.
Never log remote response bodies, tokens, WireGuard keys or profiles.
"""
import re
from urllib.parse import urlsplit
from curl_cffi import requests

AUTH = "https://auth.purevpn.com"
APP = "https://my.purevpn.com"
CLIENT_ID = "ed1ee674-0a34-4265-b4a1-141b721036eb"
TENANT_ID = "9707f41e-21a4-bbc5-dcbc-fdf6b61cc68f"
REDIRECT = APP + "/v2/api/fusionauth/login"


class PureVPNError(Exception):
    """Safe, non-secret exception for expected service errors."""
    pass


class PureVPNBlocked(PureVPNError):
    """Rate limit or access denial: do not retry automatically."""
    pass


def check_response(response, stage):
    if response.status_code in (403, 429):
        retry = response.headers.get("retry-after", "")
        retry_desc = " (Retry-After supplied)" if retry else ""
        # Never report body, cookies, URLs with query parameters or credentials.
        reason = "access denied" if response.status_code == 403 else "rate limited"
        raise PureVPNBlocked(f"{stage}: HTTP {response.status_code}, {reason}{retry_desc}")
    response.raise_for_status()



class PureVPN:
    def __init__(self):
        self.session = requests.Session(impersonate="chrome116")
        self.session.headers.update({"User-Agent": "Mozilla/5.0", "Accept-Language": "en"})
        self.subscription = None
        self.vpn_username = None

    def _onboard(self, token):
        self.session.headers.update({"Authorization": "Bearer " + token, "Accept": "application/json"})
        result = self.session.post(APP + "/v2/api/on-boarding", timeout=30)
        check_response(result, "subscription lookup")
        payload = result.json()
        if payload.get("status") is not True:
            raise PureVPNError("subscription lookup failed")
        subscription = payload["body"]["subscriptions"][0]
        self.subscription = subscription["id"]
        self.vpn_username = subscription["vpnusernames"][0]

    def login(self, username, password, cached_token=None):
        if cached_token:
            try:
                self._onboard(cached_token)
                return cached_token
            except PureVPNBlocked:
                raise
            except Exception:
                self.session.headers.pop("Authorization", None)
        preflight = self.session.get(AUTH + "/oauth2/authorize", params={
            "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "response_type": "code"}, timeout=30)
        check_response(preflight, "authorization page")
        form = {
            "captcha_token": "", "client_id": CLIENT_ID, "code_challenge": "",
            "code_challenge_method": "", "metaData.device.name": "Windows Chrome",
            "metaData.device.type": "BROWSER", "nonce": "", "pendingIdPLinkId": "",
            "redirect_uri": REDIRECT, "response_mode": "", "response_type": "code",
            "scope": "", "state": "", "tenantId": TENANT_ID, "timezone": "Europe/London",
            "user_code": "", "showPasswordField": "true",
            "loginId": username, "password": password,
        }
        result = self.session.post(AUTH + "/oauth2/authorize", data=form, headers={
            "Origin": AUTH, "Referer": AUTH + "/",
            "Content-Type": "application/x-www-form-urlencoded"}, timeout=30, allow_redirects=True)
        check_response(result, "login redirect")
        token = self.session.cookies.get("fa_token")
        if not token:
            raise PureVPNError("login did not return token; CAPTCHA or MFA may be required")
        self._onboard(token)
        return token

    def generate(self, country, city_id, private_key, public_key):
        if not re.fullmatch(r"[A-Z]{2}", country):
            raise ValueError("Country must be a two-letter country code")
        headers = {"Origin": APP, "Referer": APP + "/v2/dashboard/manual-config",
                   "Content-Type": "application/x-www-form-urlencoded"}
        result = self.session.post(APP + "/v2/api/wireguard/get-encrypt-password",
                                   data={"username": self.vpn_username}, headers=headers, timeout=30)
        check_response(result, "encrypted credential request")
        enc = result.json()
        if not enc.get("status"):
            raise PureVPNError("encrypted credential request failed")
        form = {"sUsername": self.vpn_username, "sPassword": enc["body"]["encrypPass"],
                "sCountrySlug": country, "sDeviceType": "linux",
                "sClientPublicKey": public_key, "natServer": "1",
                "sSubsId": str(self.subscription)}
        if city_id:
            form["iCityId"] = str(city_id)
        result = self.session.post(APP + "/v2/api/wireguard/get-wg-server",
                                   data=form, headers=headers, timeout=30)
        check_response(result, "WireGuard server request")
        response = result.json()
        if not response.get("status"):
            raise PureVPNError("server configuration request failed")
        body = response.get("body")
        record = body[0] if isinstance(body, list) and body else body if isinstance(body, dict) else {}
        profile = record.get("wireguard_configuration", "").replace("{clientPrivateKey}", private_key)
        if not all(re.search(r"(?mi)^\s*" + field + r"\s*=\s*\S+", profile)
                   for field in ("PrivateKey", "Address", "PublicKey", "Endpoint")):
            raise PureVPNError("incomplete WireGuard profile returned")
        if private_key not in profile:
            raise PureVPNError("WireGuard private key mismatch")
        return profile
