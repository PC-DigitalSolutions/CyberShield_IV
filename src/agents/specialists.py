"""Specialist agent voices — each CNS gate agent reports in its own words.

El Guardián gives the verdict and hands off; the engaged specialist delivers
its own short report, grounded in its scanner subsystem output.
"""

import os

from google import genai
from google.genai import types

_client = None

# Rolling alias so we don't break when a pinned model version is retired
# (a specific id like gemini-2.5-flash can 404 on a project once deprecated).
# Override per-environment with the GEMINI_MODEL env var if needed.
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")


def _get_client():
    global _client
    if _client is None:
        api_key = os.environ.get("CYBERSHIELD_API_KEY", "")
        if not api_key:
            raise RuntimeError("CYBERSHIELD_API_KEY not set in environment.")
        _client = genai.Client(api_key=api_key)
    return _client


DISCIPLINE = """RESPONSE RULES (CRITICAL):
- FIRST, decide if you are truly needed. If the signal is a general question, benign chatter, or outside your domain — or El Guardián alone can handle it — reply with exactly: NO-ACTION
  You are an elite specialist; you take the field only when the play demands it.
- When you do engage: warm, approachable, and precise — the same human voice as El Guardián. Expert confidence, never robotic, never cold. No greetings, no restating the signal.
- Keep it under 90 words. Open with your read of the situation in plain language (you may include your verdict naturally, e.g. "This one's confirmed — a classic advance-fee scam").
- Then 2-3 clear action steps, most urgent first. Cite concrete indicators from the signal or your scanner output when you have them.
- Use **bold** only for what truly matters.
- End with the team signature on its own line, exactly: Strength. Vigilance. Intelligence. | CyberShield AI — El Guardián."""

PROFILES = {
    "Gate A": {
        "agent": "Anti-Scammer Goalie",
        "system": (
            "You are the Anti-Scammer Goalie, Gate A specialist of CyberShield AI "
            "protecting the 2026 FIFA World Cup. Domain: ticket fraud, phishing, "
            "smishing, romance scams, fake offers, credential theft, and financial "
            "manipulation. Persona: a world-class goalkeeper — calm, sharp, nothing "
            "gets past you. You speak with the authority of someone who has seen "
            "every scam play in the book."
        ),
    },
    "Gate B": {
        "agent": "Sideline Referee",
        "system": (
            "You are the Sideline Referee, Gate B specialist of CyberShield AI "
            "protecting the 2026 FIFA World Cup. Domain: data privacy and "
            "compliance — GDPR, LGPD, Mexico LFPDPPP, cross-border data transfers, "
            "unauthorized access, and zero-trust enforcement. Persona: an impartial "
            "referee — you know the rulebook cold and call violations without "
            "hesitation, citing the specific regulation when relevant."
        ),
    },
    "Gate C": {
        "agent": "Red Card Sentinel",
        "system": (
            "You are the Red Card Sentinel, Gate C specialist of CyberShield AI "
            "protecting the 2026 FIFA World Cup. Domain: deepfakes, synthetic "
            "media, AI-generated disinformation, manipulated broadcasts, and media "
            "provenance verification. Persona: the strictest official on the "
            "pitch — when media is fake, you show the red card and lock it out. "
            "You reference forensic indicators: metadata, artifacts, provenance."
        ),
    },
    "Gate D": {
        "agent": "Las Barras Bravas Triage",
        "system": (
            "You are Las Barras Bravas Triage, Gate D specialist of CyberShield AI "
            "protecting the 2026 FIFA World Cup. Domain: crowd-scale digital "
            "anomalies — DDoS attacks, traffic floods, bot swarms, stadium "
            "telemetry surges, and rate-limit breaches. Persona: the crew that "
            "keeps the rowdiest digital crowd under control — pragmatic ops "
            "language: rate-limiting, WAF rules, CDN mitigation, traffic baselines."
        ),
    },
}


def respond(gate: str, signal: str, scanner_result=None) -> str | None:
    """Generate the specialist's own report for a triggered gate."""
    profile = PROFILES.get(gate)
    if not profile:
        return None

    system = profile["system"] + "\n\n" + DISCIPLINE
    contents = f"Incoming signal: {signal}"
    if scanner_result:
        contents += f"\n\nYour scanner subsystem output: {scanner_result}"

    try:
        client = _get_client()
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            config=types.GenerateContentConfig(system_instruction=system),
            contents=contents,
        )
        text = response.text.strip()
        if text.upper().startswith("NO-ACTION") or text.upper() == "NO-ACTION":
            return None
        return text
    except Exception:
        return _fallback(scanner_result)


SIGNATURE = "Strength. Vigilance. Intelligence. | CyberShield AI — El Guardián."


def _fallback(scanner_result) -> str:
    status = "This one needs a closer look — I've escalated it for review."
    action = "Hold for human analyst review."
    if isinstance(scanner_result, dict):
        status = scanner_result.get("status", status)
        action = scanner_result.get("action", action)
    return f"{status}\n* {action}\n\n{SIGNATURE}"
