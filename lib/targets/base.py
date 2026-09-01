"""Base class for target plugins."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class SprayResult:
    """Result of a single spray attempt."""
    username: str
    password: str
    status_code: int
    response: str
    target: str

    @property
    def is_success(self) -> bool:
        return self.status_code == 200


class TargetPlugin(ABC):
    """Abstract base for spray targets."""

    name: str = "base"
    description: str = "Base target plugin"

    def __init__(self, proxy_url: str = "http://changeme:changeme@127.0.0.1:1234"):
        self.proxy_url = proxy_url
        self.proxies = {"http": proxy_url, "https": proxy_url}

    @abstractmethod
    def spray(self, username: str, password: str) -> SprayResult:
        """Perform a single spray attempt."""
        ...

    @abstractmethod
    def parse_response(self, result: SprayResult) -> dict:
        """Parse the response into a structured result with verdict."""
        ...
