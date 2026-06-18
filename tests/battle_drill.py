import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.core.router import ElGuardianCNS


def print_report(title, result):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)
    print(json.dumps(result, indent=2))


def main():
    cns = ElGuardianCNS()

    scenarios = [
        {
            "name": "SCAM -> GOALIE",
            "signal": "Fans are receiving a phishing link asking for money to unlock fake ticket access.",
            "expected_primary_gate": "Gate A",
        },
        {
            "name": "DEEPFAKE -> SENTINEL",
            "signal": "Deepfake video spreading online claims the stadium gates are closed.",
            "expected_primary_gate": "Gate C",
        },
        {
            "name": "OVERLAP -> CNS ARBITER + UTR",
            "signal": "Deepfake video includes a scam payment link asking fans for money.",
            "expected_primary_gate": "Gate C",
        },
        {
            "name": "ANOMALY -> TRIAGE",
            "signal": "Massive traffic spike and crowd telemetry anomaly detected near stadium entrance.",
            "expected_primary_gate": "Gate D",
        },
        {
            "name": "COMPLIANCE -> REFEREE",
            "signal": "Unauthorized data egress and privacy compliance issue detected in access logs.",
            "expected_primary_gate": "Gate B",
        },
    ]

    print("\nCYBERSHIELD_IV PHASE III BATTLE DRILL")
    print("CNS Status:")
    print(json.dumps(cns.status(), indent=2))

    failures = 0

    for scenario in scenarios:
        result = cns.route_to_agent(scenario["signal"])
        print_report(scenario["name"], result)

        actual = result.get("primary_gate")
        expected = scenario["expected_primary_gate"]

        if actual != expected:
            failures += 1
            print(f"[FAIL] Expected {expected}, got {actual}")
        else:
            print(f"[PASS] Primary gate matched: {actual}")

        utr = result.get("utr")

        if result.get("status") == "routed" and not utr:
            failures += 1
            print("[FAIL] Routed event did not produce UTR.")
        elif utr:
            required_fields = [
                "severity",
                "agent_outputs",
                "recommended_actions",
                "signature",
                "mitre_attack_id",
            ]

            missing = [field for field in required_fields if field not in utr]

            if missing:
                failures += 1
                print(f"[FAIL] UTR missing fields: {missing}")
            else:
                print("[PASS] UTR required fields present.")

    print("\n" + "=" * 72)

    if failures:
        print(f"BATTLE DRILL COMPLETE WITH {failures} FAILURE(S).")
        sys.exit(1)

    print("BATTLE DRILL COMPLETE: ALL CHECKS PASSED.")
    sys.exit(0)


if __name__ == "__main__":
    main()
