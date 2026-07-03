"""Community scam-story store — the Anti-Scammer Goalie's training ground.

Fans share the scams that hit them or their families (with explicit consent).
Stories are scrubbed of PII, stored in SQLite, and fed back into the Goalie's
chat context — so every report the community files makes him sharper.
"""

import os
import re
import sqlite3
import threading
import time

DB_PATH = os.environ.get(
    "COMMUNITY_DB", os.path.join("data", "community_stories.db")
)

SCAM_TYPES = [
    "tickets", "phishing", "smishing", "romance", "impersonation",
    "crypto", "merch", "travel", "other",
]

# PII scrubbing — stories are anonymous by construction, but people paste
# real messages, so mask anything that looks like contact info or accounts.
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)")
_LONG_DIGITS = re.compile(r"\d{6,}")
_HANDLE = re.compile(r"(?<!\w)@\w{3,}")

# Tiny bilingual stopword set for keyword matching (EN + ES).
_STOPWORDS = {
    "the", "and", "for", "you", "your", "that", "this", "with", "from",
    "they", "them", "have", "has", "was", "were", "will", "just", "about",
    "que", "para", "con", "por", "una", "uno", "los", "las", "del", "este",
    "esta", "pero", "como", "más", "mas", "muy", "sus", "ella", "él", "ellos",
}


def _scrub(text: str) -> str:
    text = _EMAIL.sub("[email]", text)
    text = _PHONE.sub("[phone]", text)
    text = _LONG_DIGITS.sub("[number]", text)
    text = _HANDLE.sub("[handle]", text)
    return text.strip()


def _tokens(text: str) -> set:
    words = re.findall(r"[\wáéíóúñü]{4,}", text.lower())
    return {w for w in words if w not in _STOPWORDS}


# Seed stories so the community feed and the Goalie's intel are never empty
# on a fresh deploy. Marked source="seed" and shown like any other report.
_SEEDS = [
    ("Got a WhatsApp saying I won 2 tickets to the World Cup final, just pay a "
     "$50 'processing fee' through a link. The site looked exactly like FIFA's "
     "but the URL was fifa-tickets2026.win.", "tickets", "en"),
    ("Me llegó un SMS de 'FIFA' diciendo que mi boleto fue cancelado y que "
     "tenía que verificar mi tarjeta en 24 horas o perdía mi lugar. El enlace "
     "pedía el número completo y el CVV.", "smishing", "es"),
    ("A 'FIFA volunteer coordinator' on Instagram offered my cousin paid work "
     "at the Dallas matches. They asked for her passport photo and a $120 "
     "'uniform deposit' up front. No such program exists.", "impersonation", "en"),
    ("Un tipo en Facebook Marketplace vendía boletos 'verificados' para "
     "México vs Argentina en el Azteca. Pedía la mitad por transferencia "
     "antes de mandar el QR. El QR que mandó era una captura reciclada.",
     "tickets", "es"),
]


class CommunityStories:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        directory = os.path.dirname(db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._lock, self._connect() as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS stories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created REAL NOT NULL,
                    story TEXT NOT NULL,
                    scam_type TEXT NOT NULL,
                    language TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'form'
                )"""
            )
            count = con.execute("SELECT COUNT(*) FROM stories").fetchone()[0]
            if count == 0:
                now = time.time()
                con.executemany(
                    "INSERT INTO stories (created, story, scam_type, language, source) "
                    "VALUES (?, ?, ?, ?, 'seed')",
                    [(now - 86400 * (i + 2), s, t, lang)
                     for i, (s, t, lang) in enumerate(_SEEDS)],
                )

    def add(self, story: str, scam_type: str = "other",
            language: str = "", source: str = "form") -> int:
        story = _scrub(story)
        if scam_type not in SCAM_TYPES:
            scam_type = "other"
        with self._lock, self._connect() as con:
            cur = con.execute(
                "INSERT INTO stories (created, story, scam_type, language, source) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), story, scam_type, language[:8], source),
            )
            return cur.lastrowid

    def recent(self, limit: int = 20) -> list:
        with self._lock, self._connect() as con:
            rows = con.execute(
                "SELECT id, created, story, scam_type, language FROM stories "
                "ORDER BY created DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {"id": r[0], "created": r[1], "story": r[2],
             "scam_type": r[3], "language": r[4]}
            for r in rows
        ]

    def match(self, message: str, k: int = 3) -> list:
        """Top-k stored stories sharing keywords with the incoming message —
        the community intel injected into the Goalie's chat context."""
        probe = _tokens(message)
        if not probe:
            return []
        scored = []
        for s in self.recent(limit=200):
            overlap = len(probe & _tokens(s["story"]))
            if overlap >= 2:
                scored.append((overlap, s))
        scored.sort(key=lambda x: (-x[0], -x[1]["created"]))
        return [s for _, s in scored[:k]]

    def stats(self) -> dict:
        with self._lock, self._connect() as con:
            total = con.execute("SELECT COUNT(*) FROM stories").fetchone()[0]
            week = con.execute(
                "SELECT COUNT(*) FROM stories WHERE created > ?",
                (time.time() - 7 * 86400,),
            ).fetchone()[0]
            by_type = dict(con.execute(
                "SELECT scam_type, COUNT(*) FROM stories GROUP BY scam_type "
                "ORDER BY COUNT(*) DESC"
            ).fetchall())
        return {"total": total, "this_week": week, "by_type": by_type}


stories = CommunityStories()
