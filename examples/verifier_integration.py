"""Example: Adding RelayShield threat screening to a Chain of Trust verifier."""

from chain_of_trust_relayshield import ThreatScreener


def main():
    # Initialize with your RelayShield API key
    screener = ThreatScreener()  # reads RELAYSHIELD_API_KEY from environment

    # Step 1: Chain of Trust identity verification happens first
    # (using SPIFFE, ANS, DNSSEC, etc. per the reference architecture)
    # ...
    # verified_agent_id = "seller.skybound-travel.com"  # from ANS lookup
    # identity_ok = verify_chain_of_trust(...)  # existing checks pass

    # Step 2: Screen the verified identity for threats
    verified_agent_id = "seller.skybound-travel.com"

    result = screener.screen_agent(
        agent_id=verified_agent_id,
        domain="skybound-travel.com",
    )

    print(f"Verdict: {result.verdict}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"Recommendation: {result.recommendation}")

    if result.indicators:
        print(f"\nMatched {len(result.indicators)} threat indicators:")
        for ind in result.indicators[:5]:
            print(f"  - {ind}")

    # Step 3: Include in the Chain of Trust scorecard
    # The independent verifier publishes a signed scorecard.
    # Add the threat screening result alongside identity checks.
    scorecard_entry = {
        "agent_id": verified_agent_id,
        "identity_verified": True,  # from Chain of Trust checks
        "threat_screening": {
            "verdict": result.verdict,
            "confidence": result.confidence,
            "recommendation": result.recommendation,
        },
    }

    # Proceed only if both identity AND threat screening pass
    if result.recommendation == "block":
        print("\nBLOCKED: Threat screening failed despite valid identity.")
    elif result.recommendation == "review":
        print("\nREVIEW: Manual review recommended before proceeding.")
    else:
        print("\nPROCEED: Identity verified and no threats detected.")


if __name__ == "__main__":
    main()
