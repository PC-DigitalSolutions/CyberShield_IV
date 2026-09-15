"""
LiveThreatMonitor — proactive threat awareness for CyberShield_IV.

Polls Google News RSS across the four Sentinel domains — scams/fraud,
breaches/compliance, deepfakes/synthetic media, and infrastructure/DDoS —
plus a live-event defense lane, runs every headline through the existing CNS
gates (cheap, no LLM), and keeps a rolling feed of flagged threats + intel for
the dashboard to consume.

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
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from typing import Any, Dict, List, Optional

GOOGLE_NEWS_RSS = "https://news.google.com/rss/search"

# Search terms that surface fresh, current threat signal across the four
# Sentinel domains, plus one live-event defense lane. A broad relevance filter
# (below) keeps genuine cyber/scam news in and drops Google's occasional
# off-topic "related" items — so the feed stays current and varied instead of
# recirculating the same narrow set of headlines every cycle.
# Interleaved by domain (A/B/C/D/event) rather than grouped, because
# poll_once ingests queries in order and appendleft's each new item — so the
# queries near the END of this list land at the FRONT of the feed. Alternating
# domains keeps the top of the feed mixed instead of dominated by whichever
# Sentinel happens to be listed last. Gate tag in the comment for each.
QUERIES: List[str] = [
    "phishing scam",              # A
    "data breach",                # B
    "deepfake scam",              # C
    "DDoS attack",                # D
    "concert ticket scam",        # event
    "online fraud",               # A
    "ransomware attack",          # B
    "AI voice scam",              # C
    "cyber service outage",       # D
    "event ticket fraud",         # event
    "impersonation scam",         # A
    "data leak exposed records",  # B
    "deepfake video",             # C
    "crypto scam",                # A
]

# Cap on how many items a single query contributes per poll. Google News
# returns ~40+ items per query; without this, one high-volume category (e.g.
# ticket fraud) floods the 60-item deque and evicts every other Sentinel's
# findings ingested earlier in the same poll. 4 × 14 queries = 56 candidates,
# so a full poll fits the feed window with every domain represented.
PER_QUERY_CAP = 4

# Seconds to wait between successive query fetches within a poll. We used to
# fire all queries concurrently (asyncio.gather) — a burst of 14 requests from
# one IP that Google News answers with HTTP 503. Spacing them out spreads the
# poll over ~20s (well inside the 75s interval) and keeps every fetch
# succeeding. A single per-request fetch (like the dashboard's /api/intel) has
# never been throttled; the burst was the trigger.
FETCH_SPACING = 1.5

# Browser-like User-Agent. Google News RSS is far likelier to 503 an obvious
# bot UA; the dashboard route uses a real UA and is never throttled.
FETCH_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

# A headline must read as genuine cyber/scam signal to enter the feed. This is
# broad on purpose: it lets news across all four Sentinel domains through while
# dropping Google's occasional unrelated "related story" noise.
CYBER_RELEVANCE = re.compile(
    r"scam|fraud|phish|breach|leak|hack|hacked|ransomware|malware|deepfake|"
    r"\bai\b|artificial intelligence|synthetic|cyber|ddos|outage|privacy|"
    r"security|credential|password|exploit|vulnerabilit|spyware|stolen|"
    r"impersonat|counterfeit|ticket|concert|tour|festival|\bevent\b|\bfan\b",
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
        "Never send money by gift card, crypto, or bank transfer to someone you haven't verified — and never share a one-time code, even to 'confirm' your identity.",
        "If a message pressures you to 'act now or lose it,' that urgency is the scam. Slow down and verify through an official channel.",
        "Buying tickets or deals online? Use only the official seller — a link sent to you, or a resale screenshot, is how counterfeits get in.",
    ],
    "Gate B": [  # Compliance Sentinel
        "Turn on two-factor authentication and use a unique password for every important account.",
        "Never reuse your email password anywhere else — one breach then unlocks everything you own.",
        "Got an email to 'verify your details'? Open the site yourself instead of clicking the link.",
    ],
    "Gate C": [  # Deepfake Sentinel
        "Pause before sharing shocking clips — confirm them on the source's official, verified accounts first.",
        "AI-faked announcements, giveaways, and 'endorsements' spread fast. Verify the real source before you believe it.",
        "A cloned voice or video built to make you panic or act fast is a red flag — hang up and call back on a number you trust.",
    ],
    "Gate D": [  # Infrastructure Sentinel
        "During an outage, trust only the official app or site — fake 'status' and 'instant fix' links exist to harvest logins.",
        "A 'your account is locked, click here' message during a service disruption is a classic pressure scam.",
        "Expect slowdowns during major traffic surges; ignore links promising 'instant access' around them.",
    ],
}
INTEL_ADVICE = "Stay ahead of it — follow official, verified channels for security updates instead of trusting forwarded links."

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
        r"deepfake|deep fake|synthetic media|manipulated (video|image)|ai[- ]generated (video|image)|"
        r"voice clon|cloned voice|ai voice|voice[- ]?spoof|disinformation|misinformation",
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
        # of every headline the monitor assessed. Configure
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
    def _fetch(self, query: str, _retry: bool = True) -> Optional[bytes]:
        params = urllib.parse.urlencode(
            {"q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"}
        )
        req = urllib.request.Request(
            f"{GOOGLE_NEWS_RSS}?{params}",
            headers={"User-Agent": FETCH_UA},
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            # Google 503s a request it thinks is part of a burst; a single
            # short-backoff retry almost always succeeds once fetches are spaced.
            if exc.code == 503 and _retry:
                time.sleep(2.0)
                return self._fetch(query, _retry=False)
            self.last_error = f"fetch '{query}': {exc}"
            return None
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

        # Keep the feed to genuine cyber/scam signal; drop unrelated noise.
        if not CYBER_RELEVANCE.search(it["title"]):
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
        poll loop. Every headline the monitor classifies — threat or intel — is
        written as one JSON line, giving a permanent,
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
        # Fetch queries one at a time with a small gap between them, rather than
        # firing all 14 at once. The concurrent burst got Google News to answer
        # every request with HTTP 503; spacing keeps the fetches succeeding and
        # still finishes well inside the poll interval.
        for i, query in enumerate(self.queries):
            if i:
                await asyncio.sleep(FETCH_SPACING)
            raw = await asyncio.to_thread(self._fetch, query)
            if not raw:
                continue
            try:
                items = self._parse(raw)
            except Exception as exc:
                self.last_error = f"parse '{query}': {exc}"
                continue
            # Cap per query so one high-volume category can't flood the feed
            # window and evict other Sentinels' findings from the same poll.
            for it in items[:PER_QUERY_CAP]:
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
