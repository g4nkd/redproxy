"""Custom HTTP target plugin for arbitrary endpoints."""
import requests
from urllib3.exceptions import InsecureRequestWarning

from .base import TargetPlugin, SprayResult

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class CustomTarget(TargetPlugin):
    """Custom HTTP target — spray arbitrary login endpoints."""

    name = "custom"
    description = "Custom HTTP endpoint spray"

    def __init__(self, proxy_url: str = "http://changeme:changeme@127.0.0.1:1234",
                 target_url: str = "", method: str = "POST",
                 body_template: str = "", headers: dict = None,
                 success_codes: list = None):
        super().__init__(proxy_url)
        self.target_url = target_url
        self.method = method.upper()
        self.body_template = body_template
        self.custom_headers = headers or {"Content-Type": "application/x-www-form-urlencoded"}
        self.success_codes = success_codes or [200]

    def spray(self, username: str, password: str) -> SprayResult:
        body = self.body_template.replace("{username}", username).replace("{password}", password)

        try:
            resp = requests.request(
                self.method,
                self.target_url,
                proxies=self.proxies,
                headers=self.custom_headers,
                data=body,
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
                username=username, password=password,
                status_code=0, response=str(e), target=self.name,
            )

    def parse_response(self, result: SprayResult) -> dict:
        return {
            "username": result.username,
            "password": result.password,
            "status_code": result.status_code,
            "target": self.name,
            "verdict": "success" if result.status_code in self.success_codes else "failed",
            "detail": result.response[:200],
            "valid_creds": result.status_code in self.success_codes,
            "needs_attention": result.status_code in self.success_codes,
        }
