# Chain of Trust + RelayShield

Threat-intelligence screening for the [Chain of Trust](https://openagentcommerce.org) reference architecture.

Chain of Trust verifies agent **identity** across platforms using open standards (SPIFFE, Agent Name Service, OAuth). This integration adds the missing layer: **threat screening**. A verified identity tells you who the agent claims to be. RelayShield tells you whether that agent or its operator is a known threat.

## The gap

From the Chain of Trust technical case study:

> "A domain shows which organisation runs an agent, not which company stands behind the domain."

Identity verification answers "are you who you claim to be?" It does not answer "should I trust you?" A verified agent can still be malicious. Stolen credentials pass identity checks. This integration closes that gap.

## How it works

The Chain of Trust reference architecture includes an **independent verifier** role that replays checks and publishes a signed scorecard. This package adds a RelayShield threat-screening step to that verifier flow:

```
Chain of Trust identity checks (existing)
    → RelayShield threat screening (this package)
    → Combined verdict in the scorecard
```

## Installation

```bash
pip install chain-of-trust-relayshield
```

Or from source:

```bash
git clone https://github.com/nzdsf2-gif/chain-of-trust-relayshield
cd chain-of-trust-relayshield
pip install -e .
```

## Usage

```python
from chain_of_trust_relayshield import ThreatScreener

screener = ThreatScreener(api_key="your-relayshield-api-key")

# After Chain of Trust identity verification passes,
# screen the verified identity for threats
result = screener.screen_agent(
    agent_id="seller.skybound-travel.com",
    agent_card={...},  # A2A agent card from discovery
)

print(result.verdict)      # "clean", "suspicious", or "malicious"
print(result.confidence)   # 0.0 - 1.0
print(result.indicators)   # matched threat indicators
```

## API Reference

### `ThreatScreener(api_key, base_url=None)`

Creates a screener instance.

- `api_key`: Your RelayShield API key
- `base_url`: Override the API base URL (default: production)

### `screen_agent(agent_id, agent_card=None, domain=None)`

Screens a verified agent identity against the RelayShield threat corpus.

Returns a `ScreeningResult` with:
- `verdict`: "clean", "suspicious", or "malicious"
- `confidence`: float 0.0-1.0
- `indicators`: list of matched threat indicators
- `recommendation`: "proceed", "review", or "block"

### `screen_domain(domain)`

Screens a domain against the threat corpus. Useful for checking seller domains during discovery.

## Configuration

Set your API key via environment variable:

```bash
export RELAYSHIELD_API_KEY="your-key-here"
```

Or pass it directly to `ThreatScreener`.

## License

Apache 2.0
