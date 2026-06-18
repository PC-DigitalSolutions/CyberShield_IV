"""
LiveThreatMonitor — proactive World Cup threat awareness for CyberShield_IV.

Polls Google News RSS for World Cup threat + sponsor-tech signal, runs every
headline through the existing CNS gates (cheap, no LLM), and keeps a rolling
feed of flagged threats + intel for the dashboard to consume.

Two-stage design (keeps the Gemini quota safe):
  1. Cheap keyword gate (cns.detect_gates) classifies EVERY incoming headline.
  2. The expensive LLM (El Guardian) is only ever invoked on demand via the
     existing /analyze endpoint when an analyst clicks a feed item — never in
     this loop.
"""

import asyncio
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any, Dict, List, Optional

GOOGLE_NEWS_RSS = "https://news.google.com/rss/search"

# Search terms that surface World Cup threat signal + sponsor-tech intel.
# Every query is anchored to the World Cup, and a relevance filter (below)
# drops anything whose headline isn't actually about the tournament — so the
# feed stays World-Cup-only instead of generic cyber news.
QUERIES: List[str] = [
    "FIFA World Cup 2026 scam",
    "FIFA World Cup 2026 ticket fraud",
    "FIFA World Cup 2026 phishing",
    "FIFA World Cup 2026 fake tickets",
    "FIFA World Cup 2026 cyberattack",
    "FIFA World Cup 2026 cybersecurity",
    "FIFA World Cup 2026 data breach",
    "FIFA World Cup 2026 deepfake",
    "FIFA World Cup 2026 fan safety",
    "FIFA World Cup 2026 news",
    "Lenovo FIFA World Cup 2026",
    "FIFA World Cup 2026 technology",
]

# A headline must mention the tournament to enter the feed. This is what makes
# the feed "World-Cup-only" — generic DDoS/breach news gets dropped.
WC_RELEVANCE = re.compile(
    r"world cup|\bfifa\b|mundial|wc\s?2026|2026 world cup|world cup 2026",
    re.I,
)

GATE_SEVERITY = {
    "Gate C": "CRITICAL",  # Red Card Sentinel — synthetic media
    "Gate A": "HIGH",      # Anti-Scammer Goalie — fraud / phishing
    "Gate D": "HIGH",      # Las Barras Bravas Triage — traffic / DDoS
    "Gate B": "MEDIUM",    # Sideline Referee — compliance / data
}

# Plain-English, public-facing advice per gate. Multiple lines per agent so the
# feed doesn't repeat the same tip — one is chosen per headline (stable).
GATE_ADVICE = {
    "Gate A": [  # Anti-Scammer Goalie
        "Buy tickets only on FIFA's official site. Never pay by gift card or crypto, and never share verification codes.",
        "If a ticket deal pressures you to 'act fast or lose it,' that urgency is the scam. Walk away.",
        "Reselling? Use only FIFA's official resale platform — fake QR codes won't scan at the gate.",
    ],
    "Gate B": [  # Sideline Referee
        "Turn on two-factor authentication and use a unique password for ticket and travel accounts.",
        "Never reuse your email password elsewhere — one breach then unlocks everything you own.",
        "Got an email to 'verify your details'? Open the site yourself instead of clicking the link.",
    ],
    "Gate C": [  # Red Card Sentinel
        "Pause before sharing shocking clips — confirm them on official team or FIFA accounts first.",
        "AI-faked player 'announcements' spread fast. Check the verified source before you believe it.",
        "If a video seems built to enrage or panic you, treat it as fake until you've verified it.",
    ],
    "Gate D": [  # Las Barras Bravas Triage
        "Expect slow official sites near kickoff. Ignore 'instant access' links claiming to fix outages.",
        "During traffic surges, trust only the official app — fake mirror sites exist to harvest logins.",
        "A 'your account is locked, click here' message during a match is a classic pressure scam.",
    ],
}
INTEL_ADVICE = "Stay match-ready — follow official FIFA and team channels for verified updates."

# Plural/stem-tolerant patterns for headline triage. The CNS gates use strict
# word-boundary keywords tuned for user-submitted signals; news headlines need
# looser matching ("scams", "fraudsters", "cyberattack"). This lives in the
# monitor so the CNS gate logic stays untouched. CNS detect_gates is still tried
# first and wins; this is only the fallback that decides threat-vs-intel.
MONITOR_PATTERNS = {
    "Gate A": re.compile(
        r"scam|phish|fraud|counterfeit|impersonat|fake ticket|ticket(ing)? (fraud|fraudster)|crypto scam|giveaway|prize",
        re.I,
    ),
    "Gate C": re.compile(
        r"deepfake|deep fake|synthetic media|manipulated (video|image)|ai[- ]generated (video|image)|disinformation|misinformation",
        re.I,
    ),
    "Gate D": re.compile(
        r"ddos|denial[- ]of[- ]service|botnet|traffic flood|service outage|overload",
        re.I,
    ),
    "Gate B": re.compile(
        r"data breach|breach|data leak|leaked|gdpr|privacy|hacked|hacking|hacker|ransomware|malware|cyber[- ]?attack|stolen data|credential",
        re.I,
    ),
}


class LiveThreatMonitor:
    def __init__(self, cns, interval: int = 75):
        self.cns = cns
        self.interval = interval
        self.queries = QUERIES
        # Separate buffers so high-volume intel never evicts flagged threats.
        self._threats: deque = deque(maxlen=60)
        self._intel: deque = deque(maxlen=30)
        self._seen: set = set()
        self.total_seen = 0
        self.total_flagged = 0
        self.last_poll: float = 0.0
        self.last_error: Optional[str] = None
        self.running = False

    # ── fetching ────────────────────────────────────────────
    def _fetch(self, query: str) -> Optional[bytes]:
        params = urllib.parse.urlencode(
            {"q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"}
        )
        req = urllib.request.Request(
            f"{GOOGLE_NEWS_RSS}?{params}",
            headers={"User-Agent": "Mozilla/5.0 (CyberShield Live Monitor)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                return resp.read()
        except Exception as exc:  # network hiccup — skip this query this cycle
            self.last_error = f"fetch '{query}': {exc}"
            return None

    @staticmethod
    def _parse(raw: bytes) -> List[Dict[str, str]]:
        root = ET.fromstring(raw)
        items = []
        for it in root.iter("item"):
            items.append(
                {
                    "title": (it.findtext("title") or "").strip(),
                    "link": (it.findtext("link") or "").strip(),
                    "guid": (it.findtext("guid") or "").strip(),
                    "source": (it.findtext("source") or "").strip(),
                    "pubDate": (it.findtext("pubDate") or "").strip(),
                }
            )
        return items

    # ── classification ──────────────────────────────────────
    def _agent_for(self, gate: Optional[str]) -> str:
        if not gate:
            return "Intel Desk"
        try:
            return self.cns.registry.agents[gate]["name"]
        except Exception:
            return "El Guardián"

    @staticmethod
    def _advice(gate: Optional[str], title: str) -> str:
        tips = GATE_ADVICE.get(gate or "")
        if not tips:
            return INTEL_ADVICE
        # Stable per-headline pick so the same story keeps the same tip.
        idx = sum(title.encode("utf-8", "ignore")) % len(tips)
        return tips[idx]

    @staticmethod
    def _clean_title(title: str) -> str:
        # Google News appends " - Source"; drop it for a cleaner headline
        if " - " in title:
            head, _, _tail = title.rpartition(" - ")
            if head:
                return head
        return title

    def _classify(self, text: str):
        """Classify a news headline into CNS gates.

        We deliberately use the monitor's precise threat lexicon rather than
        cns.detect_gates here: the raw CNS keywords (broadcast, media, data,
        traffic, crowd, …) are tuned for scam DMs and over-trigger on ordinary
        sports news. We still resolve the primary gate + severity through the
        CNS hierarchy, so the feed maps onto the same Gate A–D taxonomy.
        """
        matched = [g for g, pat in MONITOR_PATTERNS.items() if pat.search(text)]
        if matched:
            return matched, self.cns.choose_primary_gate(matched)
        return [], None

    def _ingest(self, it: Dict[str, str]) -> None:
        ident = it["guid"] or it["link"]
        if not ident or ident in self._seen:
            return
        self._seen.add(ident)
        self.total_seen += 1

        # World-Cup-only: drop anything not about the tournament.
        if not WC_RELEVANCE.search(it["title"]):
            return

        title = self._clean_title(it["title"])
        gates, primary = self._classify(it["title"])

        if primary:
            kind = "threat"
            severity = GATE_SEVERITY.get(primary, "INFO")
        else:
            kind = "intel"
            severity = "INFO"

        record = {
            "id": ident,
            "title": title,
            "link": it["link"],
            "source": it["source"],
            "published": it["pubDate"],
            "kind": kind,
            "gates": gates,
            "primary_gate": primary,
            "agent": self._agent_for(primary),
            "severity": severity,
            "recommendation": self._advice(primary, title),
            "ts": time.time(),
        }
        if kind == "threat":
            self._threats.appendleft(record)
            self.total_flagged += 1
        else:
            self._intel.appendleft(record)

        # keep the dedup set from growing unbounded over a long session
        if len(self._seen) > 4000:
            self._seen = set(list(self._seen)[-2000:])

    # ── loop ────────────────────────────────────────────────
    async def poll_once(self) -> None:
        results = await asyncio.gather(
            *(asyncio.to_thread(self._fetch, q) for q in self.queries)
        )
        for query, raw in zip(self.queries, results):
            if not raw:
                continue
            try:
                items = self._parse(raw)
            except Exception as exc:
                self.last_error = f"parse '{query}': {exc}"
                continue
            for it in items:
                self._ingest(it)
        self.last_poll = time.time()

    async def run_forever(self) -> None:
        self.running = True
        while self.running:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_error = repr(exc)
            await asyncio.sleep(self.interval)

    # ── api ─────────────────────────────────────────────────
    def snapshot(self, limit: int = 25) -> Dict[str, Any]:
        limit = max(1, limit)
        threats = list(self._threats)
        intel = list(self._intel)
        # Threats first (newest first), then intel context fills the remainder.
        feed = (threats + intel)[:limit]
        return {
            "status": "monitoring" if self.last_poll else "starting",
            "source": "Google News RSS",
            "last_poll": self.last_poll,
            "poll_interval": self.interval,
            "queries": len(self.queries),
            "total_seen": self.total_seen,
            "total_flagged": self.total_flagged,
            "active_threats": len(threats),
            "active_intel": len(intel),
            "last_error": self.last_error,
            "threats": feed,
        }
