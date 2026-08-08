"""
LiveThreatMonitor — proactive worldwide event & concert threat awareness for
CyberShield_IV.

Polls Google News RSS for fan-directed scam signal around concert tours,
festivals, and major sporting events, runs every headline through the existing
CNS gates (cheap, no LLM), and keeps a rolling feed of flagged threats + intel
for the dashboard to consume.

Two-stage design (keeps the Gemini quota safe):
  1. Cheap keyword gate (cns.detect_gates) classifies EVERY incoming headline.
  2. The expensive LLM (El Guardian) is only ever invoked on demand via the
     existing /analyze endpoint when an analyst clicks a feed item — never in
     this loop.
"""

import asyncio
import json
import os
import re
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any, Dict, List, Optional

GOOGLE_NEWS_RSS = "https://news.google.com/rss/search"

# Search terms that surface worldwide live-event & concert threat signal —
# fan-directed scams around concert tours, festivals, and major sporting events.
# Every query is event-anchored, and a relevance filter (below) drops anything
# whose headline isn't actually about live events — so the feed stays
# event/concert-scoped instead of turning into generic cyber news.
QUERIES: List[str] = [
    "concert ticket scam",
    "concert presale scam",
    "tour ticket fraud",
    "festival ticket scam",
    "event ticket phishing",
    "fake concert tickets",
    "ticket resale fraud",
    "meet and greet scam",
    "deepfake celebrity giveaway",
    "sports event ticket fraud",
    "Ticketmaster scam",
    "sold out show ticket scam",
]

# A headline must be about a live event to enter the feed. This is what keeps
# the feed event/concert-scoped — generic, unrelated cyber news gets dropped.
EVENT_RELEVANCE = re.compile(
    r"ticket|concert|tour|festival|\bevent\b|presale|pre-sale|fan|\bshow\b|"
    r"arena|stadium|world cup|olympic|super bowl|match|gig|venue|artist",
    re.I,
)

GATE_SEVERITY = {
    "Gate C": "CRITICAL",  # Deepfake Sentinel — synthetic media
    "Gate A": "HIGH",      # Anti-Scam Sentinel — fraud / phishing
    "Gate D": "HIGH",      # Infrastructure Sentinel — traffic / DDoS
    "Gate B": "MEDIUM",    # Compliance Sentinel — compliance / data
}

# Plain-English, public-facing advice per gate. Multiple lines per agent so the
# feed doesn't repeat the same tip — one is chosen per headline (stable).
GATE_ADVICE = {
    "Gate A": [  # Anti-Scam Sentinel
        "Buy tickets only from the venue's or artist's official seller. Never pay by gift card, crypto, or bank transfer, and never share verification codes.",
        "If a ticket deal pressures you to 'act fast or lose it,' that urgency is the scam. Walk away.",
        "Reselling? Use only the event's official resale platform — screenshots and fake QR codes won't scan at the gate.",
    ],
    "Gate B": [  # Compliance Sentinel
        "Turn on two-factor authentication and use a unique password for ticket and travel accounts.",
        "Never reuse your email password elsewhere — one breach then unlocks everything you own.",
        "Got an email to 'verify your details'? Open the site yourself instead of clicking the link.",
    ],
    "Gate C": [  # Deepfake Sentinel
        "Pause before sharing shocking clips — confirm them on the artist's or organizer's official accounts first.",
        "AI-faked 'announcements' and giveaways spread fast. Check the verified source before you believe it.",
        "If a video seems built to enrage or panic you, treat it as fake until you've verified it.",
    ],
    "Gate D": [  # Infrastructure Sentinel
        "Expect slow official sites at on-sale time. Ignore 'instant access' links claiming to fix outages.",
        "During traffic surges, trust only the official app or site — fake mirror sites exist to harvest logins.",
        "A 'your account is locked, click here' message during an on-sale is a classic pressure scam.",
    ],
}
INTEL_ADVICE = "Stay event-ready — follow official venue, artist, and organizer channels for verified updates."

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
    def __init__(self, cns, interval: int = 75, log_path: Optional[str] = None):
        self.cns = cns
        self.interval = interval
        self.queries = QUERIES
        # Separate buffers so high-volume intel never evicts flagged threats.
        self._threats: deque = deque(maxlen=60)
        self._intel: deque = deque(maxlen=30)
        self._seen: set = set()
        self.total_seen = 0
        self.total_flagged = 0
        self.total_persisted = 0
        self.last_poll: float = 0.0
        self.last_error: Optional[str] = None
        self.running = False

        # Durable archive. The in-memory deques above are a rolling window that
        # resets on restart; this append-only JSONL log is the permanent record
        # of every World-Cup-relevant headline the monitor assessed. Configure
        # the path with CYBERSHIELD_THREAT_LOG, or set it to "off" to disable.
        if log_path is None:
            log_path = os.environ.get("CYBERSHIELD_THREAT_LOG", os.path.join("data", "threat_log.jsonl"))
        if not log_path or str(log_path).strip().lower() in ("off", "none", "disabled"):
            self.log_path: Optional[str] = None
        else:
            self.log_path = log_path
            try:
                os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
            except OSError as exc:  # keep the path; writes will retry and report
                self.last_error = f"log init: {exc}"

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

        # Event/concert-scoped: drop anything not about a live event.
        if not EVENT_RELEVANCE.search(it["title"]):
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

        # Write it to the durable archive before it can age out of the window.
        self._persist(record)

        # keep the dedup set from growing unbounded over a long session
        if len(self._seen) > 4000:
            self._seen = set(list(self._seen)[-2000:])

    # ── durable archive ─────────────────────────────────────
    def _persist(self, record: Dict[str, Any]) -> None:
        """Append one assessed record to the JSONL archive.

        Best-effort: a disk error is recorded to last_error but never breaks the
        poll loop. Every World-Cup-relevant headline the monitor classifies —
        threat or intel — is written as one JSON line, giving a permanent,
        append-only history that survives process restarts, unlike the
        in-memory rolling window the dashboard reads from.
        """
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.total_persisted += 1
        except OSError as exc:
            self.last_error = f"log write: {exc}"

    def history(self, limit: int = 100, kind: Optional[str] = None) -> Dict[str, Any]:
        """Read back the durable archive, newest first.

        `kind` filters to "threat" or "intel". Reads the whole log and returns
        the tail — fine at feed scale; swap for an indexed store if the archive
        ever grows large.
        """
        limit = max(1, min(limit, 1000))
        if not self.log_path or not os.path.exists(self.log_path):
            return {"status": "empty", "log_path": self.log_path, "count": 0,
                    "returned": 0, "records": []}
        records: List[Dict[str, Any]] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue  # skip a torn/partial line
                    if kind and rec.get("kind") != kind:
                        continue
                    records.append(rec)
        except OSError as exc:
            return {"status": "error", "log_path": self.log_path,
                    "error": str(exc), "count": 0, "returned": 0, "records": []}
        total = len(records)
        tail = records[-limit:][::-1]  # newest first
        return {
            "status": "ok",
            "log_path": self.log_path,
            "count": total,
            "returned": len(tail),
            "records": tail,
        }

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
            "total_persisted": self.total_persisted,
            "archive_enabled": bool(self.log_path),
            "active_threats": len(threats),
            "active_intel": len(intel),
            "last_error": self.last_error,
            "threats": feed,
        }
