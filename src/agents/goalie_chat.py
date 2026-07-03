"""Anti-Scammer Goalie chat — Gate A's own conversation lane.

Multi-turn chat with the Goalie persona, grounded in community-reported scam
stories. Stateless: the frontend sends the running history with each turn.
"""

from google.genai import types

from src.agents.specialists import PROFILES, _get_client

CHAT_DISCIPLINE = """CHAT RULES (CRITICAL — this is a live conversation, not a report):
- You are chatting one-on-one with a fan in your goal box. Warm, sharp, human — a keeper who has seen every scam play in the book. Match the user's language automatically (English, Spanish, anything).
- Keep each reply under 100 words. Plain language first ("This one smells like a fake ticket play"), then the concrete next moves. **Bold** only what truly matters.
- Ask ONE follow-up question when you genuinely need it to make the call (who sent it, what link, did they pay). Never interrogate.
- When [COMMUNITY INTEL] appears below the user's message, it is real reports from other fans. If a report matches the user's situation, say so naturally — "you're not alone, the community has flagged this exact play" — and cite the pattern, never the full story verbatim.
- If the user shares their own scam experience (it happened to them or someone they know), close your reply by inviting them once — never twice — to add it anonymously to the community intel wall so it protects the next fan. The dashboard has a button for that; just point to it.
- No signature line in chat. You are the Goalie, in the box, talking — not filing a report.
- Never ask for or repeat personal data (card numbers, passwords, addresses). If the user pastes any, tell them to redact it and never share it with anyone who asked for it."""

SYSTEM = PROFILES["Gate A"]["system"] + "\n\n" + CHAT_DISCIPLINE

_FALLBACK = (
    "My AI engine is offline right now, but here's the keeper's rule of thumb: "
    "**anyone rushing you to pay or verify is the scam**. Don't click the link, "
    "don't send money, and report the sender. I'll be back on my line shortly."
)


def chat(message: str, history: list | None = None, intel_block: str | None = None) -> str:
    """One chat turn. `history` is a list of {"role": "user"|"model", "text": str}."""
    contents = []
    for turn in (history or [])[-12:]:
        role = "model" if turn.get("role") == "model" else "user"
        text = (turn.get("text") or "").strip()
        if text:
            contents.append(
                types.Content(role=role, parts=[types.Part(text=text)])
            )

    final = (message or "").strip()
    if intel_block:
        final += f"\n\n[COMMUNITY INTEL — real reports from other fans]:\n{intel_block}"
    contents.append(types.Content(role="user", parts=[types.Part(text=final)]))

    try:
        client = _get_client()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(system_instruction=SYSTEM),
            contents=contents,
        )
        return response.text.strip()
    except Exception:
        return _FALLBACK


def build_intel_block(matches: list, stats: dict) -> str | None:
    """Format matched community stories for injection into the chat context."""
    if not matches:
        return None
    lines = [
        f"- [{m['scam_type']}] {m['story'][:280]}"
        for m in matches
    ]
    total = stats.get("total", 0)
    week = stats.get("this_week", 0)
    lines.append(
        f"(Community wall: {total} reports total, {week} this week.)"
    )
    return "\n".join(lines)
