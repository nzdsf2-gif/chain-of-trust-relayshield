"""RelayShield threat screening for Chain of Trust agent verification."""

import os
from dataclasses import dataclass, field
from typing import Optional
import urllib.request
import urllib.error
import json


@dataclass
class ScreeningResult:
    """Result of screening an agent or domain against the threat corpus."""
    verdict: str  # "clean", "suspicious", or "malicious"
    confidence: float  # 0.0 - 1.0
    indicators: list = field(default_factory=list)
    recommendation: str = "proceed"  # "proceed", "review", or "block"
    agent_id: Optional[str] = None


class ThreatScreener:
    """
    Screens Chain of Trust verified agent identities against the
    RelayShield threat intelligence corpus.

    Use after Chain of Trust identity verification passes. Identity
    tells you who the agent claims to be; this tells you whether
    that identity is associated with known threats.
    """

    DEFAULT_BASE_URL = "https://api.relayshield.net"

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key or os.environ.get("RELAYSHIELD_API_KEY")
        if not self.api_key:
            raise ValueError(
                "API key required. Pass api_key or set RELAYSHIELD_API_KEY."
            )
        self.base_url = (base_url or self.DEFAULT_BASE_URL).rstrip("/")

    def _post(self, path: str, payload: dict) -> dict:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "X-RS-API-KEY": self.api_key,
                "User-Agent": "chain-of-trust-relayshield/0.1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"RelayShield API error {e.code}: {e.read().decode()[:200]}")

    def screen_agent(
        self,
        agent_id: str,
        agent_card: Optional[dict] = None,
        domain: Optional[str] = None,
    ) -> ScreeningResult:
        """
        Screen a Chain of Trust verified agent against the threat corpus.

        Args:
            agent_id: The verified agent identifier (e.g., domain from ANS)
            agent_card: Optional A2A agent card from discovery
            domain: Optional domain to screen alongside the agent

        Returns:
            ScreeningResult with verdict, confidence, and indicators
        """
        # Agent IDs in Chain of Trust are domain-based (ANS).
        # Use explicit domain if given, otherwise treat agent_id as domain.
        check_domain = domain or agent_id

        resp = self._post("/v1/metered/domain", {"domain": check_domain})
        return self._parse_result(resp, agent_id)

    def screen_domain(self, domain: str) -> ScreeningResult:
        """
        Screen a domain against the threat corpus.
        Useful during Chain of Trust discovery phase.
        """
        resp = self._post("/v1/metered/domain", {"domain": domain})
        return self._parse_result(resp, domain)

    def _parse_result(self, resp: dict, subject: str) -> ScreeningResult:
        verdict = resp.get("verdict", "clean")
        confidence = float(resp.get("confidence", 0.0))
        indicators = resp.get("indicators", [])

        recommendation = {
            "clean": "proceed",
            "suspicious": "review",
            "malicious": "block",
        }.get(verdict, "review")

        return ScreeningResult(
            verdict=verdict,
            confidence=confidence,
            indicators=indicators,
            recommendation=recommendation,
            agent_id=subject,
        )
