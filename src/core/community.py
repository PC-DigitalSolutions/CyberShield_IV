"""Community scam-story store — the Anti-Scammer Goalie's training ground.

Fans share the scams that hit them or their families (with explicit consent).
Stories are scrubbed of PII, stored durably, and fed back into the Goalie's
chat context — so every report the community files makes him sharper.

Storage backends:
- SQLite (default, local dev): data/community_stories.db
- Postgres (production): set DATABASE_URL (e.g. Neon/Supabase) and stories
  survive redeploys. Same schema, same API.

Also keeps a privacy-first beta telemetry log: event metadata only — never
chat text, never story text, never IPs.
"""

import json
import os
import re
import sqlite3
import threading
import time

DB_PATH = os.environ.get(
    "COMMUNITY_DB", os.path.join("data", "community_stories.db")
)
DATABASE_URL = os.environ.get("DATABASE_URL", "")

SCAM_TYPES = [
    "romance", "dating", "sugar", "sextortion",
    "tickets", "phishing", "smishing", "impersonation",
    "crypto", "marketplace", "jobs", "merch", "travel", "other",
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


# ── Troll / spam guard for story submissions ─────────────────────────────
_URLS = re.compile(r"https?://|www\.", re.I)
_REPEAT = re.compile(r"(.)\1{7,}")
# Minimal hard-block list (EN/ES hate slurs). Deliberately short: the goal is
# blocking drive-by trolling on a public wall, not policing victims' language.
_BLOCKED_WORDS = re.compile(
    r"\b(nigger|nigga|faggot|tranny|spic|wetback|kike|chink|retard(ed)?|"
    r"puto\s+de\s+mierda|pinche\s+put[oa])\b", re.I,
)


def validate_story(story: str) -> str | None:
    """Returns a rejection reason, or None if the story is acceptable."""
    text = story.strip()
    if len(text) < 20:
        return "Story is too short — tell us a little more so it can help someone."
    if len(_URLS.findall(text)) > 2:
        return "Too many links — describe what happened instead of pasting URLs."
    if _REPEAT.search(text):
        return "That doesn't look like a real story."
    letters = re.findall(r"[a-záéíóúñü]", text, re.I)
    if len(letters) < len(text) * 0.4:
        return "That doesn't look like a real story."
    if _BLOCKED_WORDS.search(text):
        return "Hate speech doesn't go on the wall."
    return None


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
    ("A 'sugar daddy' on Instagram offered me $500 a week just to chat. All I "
     "had to do was buy a $50 gift card first to 'prove loyalty' — then he'd "
     "'refund it with my first allowance.' Blocked him, but he had hundreds "
     "of followers doing the same thing.", "sugar", "en"),
    ("Matched with a guy on a dating app, super sweet for two weeks, then his "
     "'mom had a medical emergency' and he needed $200 by Zelle. When I "
     "hesitated he got angry and guilt-tripped me. Classic romance play — "
     "the profile disappeared the next day.", "dating", "en"),
    ("Conocí a alguien en una app, pasamos a videollamada y grabó la sesión "
     "sin que yo supiera. Después amenazó con mandársela a mi familia si no "
     "pagaba $300. NO pagué: guardé la evidencia, lo bloqueé y lo reporté a "
     "la app. Nunca mandó nada — es su juego de miedo.", "sextortion", "es"),
]


class CommunityStories:
    def __init__(self, db_path: str = DB_PATH, database_url: str = DATABASE_URL):
        self._pg = bool(database_url)
        self._url = database_url
        self.db_path = db_path
        self._lock = threading.Lock()

        # Prefer Postgres for durability, but a bad/unreachable DATABASE_URL
        # must never crash the whole service. Fall back to SQLite and log
        # loudly so the operator knows stories won't persist until it's fixed.
        if self._pg:
            try:
                self._init_db()
                return
            except Exception as exc:
                print(
                    f"[community] WARNING: Postgres init failed ({exc!r}). "
                    "Falling back to EPHEMERAL SQLite — community stories will "
                    "NOT persist across restarts until DATABASE_URL is fixed.",
                    flush=True,
                )
                self._pg = False

        directory = os.path.dirname(self.db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._init_db()

    # ── backend plumbing ──────────────────────────────────────────────
    @property
    def backend(self) -> str:
        return "postgres" if self._pg else "sqlite"

    def _connect(self):
        if self._pg:
            import psycopg
            return psycopg.connect(self._url)
        return sqlite3.connect(self.db_path)

    def _q(self, sql: str) -> str:
        """Translate '?' placeholders for the active backend."""
        return sql.replace("?", "%s") if self._pg else sql

    def _init_db(self):
        id_col = ("BIGSERIAL PRIMARY KEY" if self._pg
                  else "INTEGER PRIMARY KEY AUTOINCREMENT")
        with self._lock, self._connect() as con:
            cur = con.cursor()
            cur.execute(
                f"""CREATE TABLE IF NOT EXISTS stories (
                    id {id_col},
                    created DOUBLE PRECISION NOT NULL,
                    story TEXT NOT NULL,
                    scam_type TEXT NOT NULL,
                    language TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'form',
                    hidden INTEGER NOT NULL DEFAULT 0
                )"""
            )
            cur.execute(
                f"""CREATE TABLE IF NOT EXISTS events (
                    id {id_col},
                    ts DOUBLE PRECISION NOT NULL,
                    event TEXT NOT NULL,
                    meta TEXT NOT NULL DEFAULT '{{}}'
                )"""
            )
            # SQLite migration: add `hidden` to pre-existing tables.
            if not self._pg:
                cols = [r[1] for r in cur.execute("PRAGMA table_info(stories)").fetchall()]
                if "hidden" not in cols:
                    cur.execute("ALTER TABLE stories ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0")
            # Seed top-up: insert any seed story not already present, so
            # existing databases pick up new seeds without duplicating.
            now = time.time()
            cur.execute("SELECT story FROM stories WHERE source = 'seed'")
            existing = {r[0] for r in cur.fetchall()}
            for i, (s, t, lang) in enumerate(_SEEDS):
                if s not in existing:
                    cur.execute(
                        self._q("INSERT INTO stories (created, story, scam_type, language, source) "
                                "VALUES (?, ?, ?, ?, 'seed')"),
                        (now - 86400 * (i + 2), s, t, lang),
                    )
            con.commit()

    # ── stories ───────────────────────────────────────────────────────
    def add(self, story: str, scam_type: str = "other",
            language: str = "", source: str = "form") -> int:
        story = _scrub(story)
        if scam_type not in SCAM_TYPES:
            scam_type = "other"
        with self._lock, self._connect() as con:
            cur = con.cursor()
            if self._pg:
                cur.execute(
                    self._q("INSERT INTO stories (created, story, scam_type, language, source) "
                            "VALUES (?, ?, ?, ?, ?) RETURNING id"),
                    (time.time(), story, scam_type, language[:8], source),
                )
                new_id = cur.fetchone()[0]
            else:
                c = cur.execute(
                    "INSERT INTO stories (created, story, scam_type, language, source) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (time.time(), story, scam_type, language[:8], source),
                )
                new_id = c.lastrowid
            con.commit()
            return new_id

    def recent(self, limit: int = 20, include_hidden: bool = False) -> list:
        where = "" if include_hidden else "WHERE hidden = 0"
        with self._lock, self._connect() as con:
            cur = con.cursor()
            cur.execute(
                self._q(f"SELECT id, created, story, scam_type, language FROM stories "
                        f"{where} ORDER BY created DESC LIMIT ?"),
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {"id": r[0], "created": r[1], "story": r[2],
             "scam_type": r[3], "language": r[4]}
            for r in rows
        ]

    def hide(self, story_id: int) -> bool:
        """Soft-delete a story from the public wall (moderation)."""
        with self._lock, self._connect() as con:
            cur = con.cursor()
            cur.execute(self._q("UPDATE stories SET hidden = 1 WHERE id = ?"), (story_id,))
            changed = cur.rowcount
            con.commit()
        return changed > 0

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
            cur = con.cursor()
            cur.execute("SELECT COUNT(*) FROM stories WHERE hidden = 0")
            total = cur.fetchone()[0]
            cur.execute(
                self._q("SELECT COUNT(*) FROM stories WHERE hidden = 0 AND created > ?"),
                (time.time() - 7 * 86400,),
            )
            week = cur.fetchone()[0]
            cur.execute(
                "SELECT scam_type, COUNT(*) FROM stories WHERE hidden = 0 "
                "GROUP BY scam_type ORDER BY COUNT(*) DESC"
            )
            by_type = dict(cur.fetchall())
        return {"total": total, "this_week": week, "by_type": by_type}

    # ── beta telemetry (metadata only — never message or story text) ──
    def log_event(self, event: str, **meta):
        try:
            with self._lock, self._connect() as con:
                cur = con.cursor()
                cur.execute(
                    self._q("INSERT INTO events (ts, event, meta) VALUES (?, ?, ?)"),
                    (time.time(), event, json.dumps(meta)),
                )
                con.commit()
        except Exception:
            pass  # telemetry must never break the product

    def beta_report(self, days: int = 14) -> dict:
        since = time.time() - days * 86400
        with self._lock, self._connect() as con:
            cur = con.cursor()
            cur.execute(self._q("SELECT ts, event, meta FROM events WHERE ts > ?"), (since,))
            rows = cur.fetchall()

        by_event: dict = {}
        by_day: dict = {}
        langs: dict = {}
        chat_total = chat_with_intel = 0
        msg_lens: list = []
        for ts, event, meta in rows:
            by_event[event] = by_event.get(event, 0) + 1
            day = time.strftime("%Y-%m-%d", time.gmtime(ts))
            by_day.setdefault(day, {})
            by_day[day][event] = by_day[day].get(event, 0) + 1
            try:
                m = json.loads(meta)
            except Exception:
                m = {}
            if lang := m.get("lang"):
                langs[lang] = langs.get(lang, 0) + 1
            if event == "chat":
                chat_total += 1
                if m.get("matches"):
                    chat_with_intel += 1
                if m.get("msg_len"):
                    msg_lens.append(m["msg_len"])

        return {
            "window_days": days,
            "backend": self.backend,
            "events_total": len(rows),
            "by_event": by_event,
            "by_day": dict(sorted(by_day.items())),
            "languages": langs,
            "chat": {
                "turns": chat_total,
                "community_intel_hit_rate": round(chat_with_intel / chat_total, 3) if chat_total else 0,
                "avg_message_chars": round(sum(msg_lens) / len(msg_lens)) if msg_lens else 0,
            },
            "stories": self.stats(),
        }


stories = CommunityStories()
