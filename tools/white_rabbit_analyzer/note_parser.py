"""White Rabbit ransom note parser -- IOC extraction from .scrypt.txt files.

Parses White Rabbit ransomware ransom notes to extract indicators of
compromise (IOCs) including email addresses, Tor/onion URLs, Bitcoin
wallet addresses, TOX messenger IDs, victim identifiers, payment
deadlines, and data volume claims.

White Rabbit ransom notes are typically dropped as ``<filename>.scrypt.txt``
alongside each encrypted file.  They follow a recognisable template that
includes contact information, threats regarding data publication, and a
unique victim reference number.

Designed for Python 3.10+.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for IOC extraction
# ---------------------------------------------------------------------------

_RE_EMAIL = re.compile(r"[\w.-]+@[\w.-]+\.\w{2,}")
_SUSPICIOUS_EMAIL_DOMAINS = {
    "protonmail.com",
    "protonmail.ch",
    "proton.me",
    "tutanota.com",
    "tutanota.de",
    "tuta.io",
    "onionmail.org",
    "onionmail.com",
}

_RE_ONION_URL = re.compile(r"https?://[\w.-]+\.onion[\w/.-]*")
_RE_ONION_DOMAIN = re.compile(r"[\w.-]+\.onion")

# Legacy (1... or 3...) and Bech32 (bc1...) Bitcoin addresses.
_RE_BTC_LEGACY = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_RE_BTC_BECH32 = re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,87}\b")

# TOX IDs are 76 uppercase hexadecimal characters.
_RE_TOX_ID = re.compile(r"\b[A-F0-9]{76}\b")

# Victim / reference identifiers.
_RE_VICTIM_ID = re.compile(
    r"(?:your\s+id|reference|victim\s+id|personal\s+id)\s*[:=]\s*(\S+)",
    re.IGNORECASE,
)

# Date-like patterns and relative deadlines.
_RE_DATE = re.compile(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}")
_RE_DAYS = re.compile(r"\d+\s*days?", re.IGNORECASE)

# File counts and data volume claims.
_RE_FILE_COUNT = re.compile(r"(\d[\d,]*)\s*files?", re.IGNORECASE)
_RE_DATA_SIZE = re.compile(
    r"(\d+(?:\.\d+)?)\s*(TB|GB|MB|KB)", re.IGNORECASE
)

# Generic URL extraction (non-onion).
_RE_URL = re.compile(r"https?://[^\s<>\"']+")

# Ransom-note filename globs (used by :meth:`NoteParser.parse_directory`).
_NOTE_GLOBS: list[str] = [
    "*.scrypt.txt",
    "*README*.txt",
    "*DECRYPT*.txt",
    "*RESTORE*.txt",
    "*RECOVER*.txt",
]


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class RansomNote:
    """Parsed representation of a single White Rabbit ransom note.

    Attributes
    ----------
    file_path:
        Filesystem path to the original note file.
    raw_text:
        Full contents of the note as read from disk.
    victim_id:
        Unique victim/reference identifier extracted from the note, if
        present.
    emails:
        Contact email addresses (filtered for suspicious domains).
    onion_urls:
        Tor ``.onion`` URLs used for negotiation portals.
    btc_addresses:
        Bitcoin wallet addresses (legacy and bech32 formats).
    tox_ids:
        TOX messenger identifiers.
    deadlines:
        Extracted date/time strings or relative deadline phrases.
    claimed_file_count:
        Number of files the threat actor claims to have encrypted or
        exfiltrated, if stated.
    claimed_data_size:
        Human-readable data volume string (e.g. ``"1.5 TB"``), if stated.
    other_urls:
        Non-onion URLs found in the note.
    iocs:
        All IOCs consolidated into a single dict keyed by type for easy
        downstream consumption.
    """

    file_path: Path
    raw_text: str
    victim_id: str | None = None
    emails: list[str] = field(default_factory=list)
    onion_urls: list[str] = field(default_factory=list)
    btc_addresses: list[str] = field(default_factory=list)
    tox_ids: list[str] = field(default_factory=list)
    deadlines: list[str] = field(default_factory=list)
    claimed_file_count: int | None = None
    claimed_data_size: str | None = None
    other_urls: list[str] = field(default_factory=list)
    iocs: dict[str, list[str]] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class NoteParser:
    """Extract IOCs and intelligence from White Rabbit ransom notes."""

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse_file(self, file_path: Path) -> RansomNote:
        """Read and parse a single ransom note file.

        Parameters
        ----------
        file_path:
            Path to a ``.scrypt.txt`` (or similarly named) ransom note.

        Returns
        -------
        RansomNote
            Parsed note with all extracted IOCs.

        Raises
        ------
        FileNotFoundError
            If *file_path* does not exist.
        """
        file_path = Path(file_path)
        logger.info("Parsing ransom note: %s", file_path)

        text = file_path.read_text(encoding="utf-8", errors="replace")

        emails = self._extract_emails(text)
        onion_urls = self._extract_onion_urls(text)
        btc_addresses = self._extract_btc_addresses(text)
        tox_ids = self._extract_tox_ids(text)
        victim_id = self._extract_victim_id(text)
        deadlines = self._extract_deadlines(text)
        other_urls = self._extract_other_urls(text, onion_urls)

        # File count claim.
        claimed_file_count: int | None = None
        fc_match = _RE_FILE_COUNT.search(text)
        if fc_match:
            try:
                claimed_file_count = int(fc_match.group(1).replace(",", ""))
            except ValueError:
                pass

        # Data size claim.
        claimed_data_size: str | None = None
        ds_match = _RE_DATA_SIZE.search(text)
        if ds_match:
            claimed_data_size = f"{ds_match.group(1)} {ds_match.group(2).upper()}"

        # Consolidate all IOCs by type.
        iocs: dict[str, list[str]] = {}
        if emails:
            iocs["email"] = emails
        if onion_urls:
            iocs["onion_url"] = onion_urls
        if btc_addresses:
            iocs["btc_address"] = btc_addresses
        if tox_ids:
            iocs["tox_id"] = tox_ids
        if victim_id:
            iocs["victim_id"] = [victim_id]
        if other_urls:
            iocs["url"] = other_urls

        note = RansomNote(
            file_path=file_path,
            raw_text=text,
            victim_id=victim_id,
            emails=emails,
            onion_urls=onion_urls,
            btc_addresses=btc_addresses,
            tox_ids=tox_ids,
            deadlines=deadlines,
            claimed_file_count=claimed_file_count,
            claimed_data_size=claimed_data_size,
            other_urls=other_urls,
            iocs=iocs,
        )

        total_iocs = sum(len(v) for v in iocs.values())
        logger.info(
            "Extracted %d IOC(s) from %s", total_iocs, file_path.name
        )
        return note

    def parse_directory(self, directory: Path) -> list[RansomNote]:
        """Find and parse all ransom notes under *directory*.

        Searches recursively for files matching common White Rabbit note
        naming patterns: ``*.scrypt.txt``, ``*README*.txt``,
        ``*DECRYPT*.txt``, ``*RESTORE*.txt``, and ``*RECOVER*.txt``.

        Parameters
        ----------
        directory:
            Root directory to scan.

        Returns
        -------
        list[RansomNote]
            Parsed notes, one per file found.
        """
        directory = Path(directory)
        if not directory.is_dir():
            logger.error("Not a directory: %s", directory)
            return []

        # Collect candidate files, deduplicating paths.
        candidates: set[Path] = set()
        for pattern in _NOTE_GLOBS:
            for match in directory.rglob(pattern):
                if match.is_file():
                    candidates.add(match.resolve())

        if not candidates:
            logger.warning("No ransom notes found in %s", directory)
            return []

        logger.info(
            "Found %d candidate ransom note(s) in %s",
            len(candidates),
            directory,
        )

        results: list[RansomNote] = []
        for note_path in sorted(candidates):
            try:
                note = self.parse_file(note_path)
                results.append(note)
            except Exception as exc:
                logger.error("Failed to parse %s: %s", note_path, exc)

        return results

    # ------------------------------------------------------------------
    # IOC extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_emails(text: str) -> list[str]:
        """Extract email addresses from *text*, filtering for suspicious domains.

        Only emails whose domain portion matches known threat-actor
        favourites (ProtonMail, Tutanota, OnionMail) are returned.

        Parameters
        ----------
        text:
            Raw ransom note content.

        Returns
        -------
        list[str]
            Deduplicated list of suspicious email addresses.
        """
        all_emails = _RE_EMAIL.findall(text)
        suspicious: list[str] = []
        seen: set[str] = set()
        for email in all_emails:
            lower = email.lower()
            domain = lower.split("@", 1)[-1]
            if domain in _SUSPICIOUS_EMAIL_DOMAINS and lower not in seen:
                suspicious.append(email)
                seen.add(lower)
        return suspicious

    @staticmethod
    def _extract_onion_urls(text: str) -> list[str]:
        """Extract Tor .onion URLs and bare domains from *text*.

        Parameters
        ----------
        text:
            Raw ransom note content.

        Returns
        -------
        list[str]
            Deduplicated list of onion URLs/domains.
        """
        urls: list[str] = []
        seen: set[str] = set()

        # Full URLs first (higher fidelity).
        for url in _RE_ONION_URL.findall(text):
            lower = url.lower()
            if lower not in seen:
                urls.append(url)
                seen.add(lower)

        # Bare domains that were not already captured inside a full URL.
        for domain in _RE_ONION_DOMAIN.findall(text):
            lower = domain.lower()
            if lower not in seen:
                urls.append(domain)
                seen.add(lower)

        return urls

    @staticmethod
    def _extract_btc_addresses(text: str) -> list[str]:
        """Extract Bitcoin wallet addresses from *text*.

        Covers both legacy (``1...`` / ``3...``) and Bech32 (``bc1...``)
        address formats.

        Parameters
        ----------
        text:
            Raw ransom note content.

        Returns
        -------
        list[str]
            Deduplicated Bitcoin addresses.
        """
        addresses: list[str] = []
        seen: set[str] = set()

        for addr in _RE_BTC_LEGACY.findall(text):
            if addr not in seen:
                addresses.append(addr)
                seen.add(addr)

        for addr in _RE_BTC_BECH32.findall(text):
            if addr not in seen:
                addresses.append(addr)
                seen.add(addr)

        return addresses

    @staticmethod
    def _extract_tox_ids(text: str) -> list[str]:
        """Extract TOX messenger IDs from *text*.

        TOX IDs are 76-character uppercase hexadecimal strings.

        Parameters
        ----------
        text:
            Raw ransom note content.

        Returns
        -------
        list[str]
            Deduplicated TOX IDs.
        """
        ids: list[str] = []
        seen: set[str] = set()
        for tox_id in _RE_TOX_ID.findall(text):
            if tox_id not in seen:
                ids.append(tox_id)
                seen.add(tox_id)
        return ids

    @staticmethod
    def _extract_victim_id(text: str) -> str | None:
        """Extract the victim/reference identifier from *text*.

        Looks for patterns like ``Your ID: XXXXX`` or
        ``Reference: XXXXX``.

        Parameters
        ----------
        text:
            Raw ransom note content.

        Returns
        -------
        str | None
            The victim ID string, or ``None`` if not found.
        """
        match = _RE_VICTIM_ID.search(text)
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def _extract_deadlines(text: str) -> list[str]:
        """Extract deadline dates and relative time phrases from *text*.

        Parameters
        ----------
        text:
            Raw ransom note content.

        Returns
        -------
        list[str]
            Deduplicated deadline strings.
        """
        deadlines: list[str] = []
        seen: set[str] = set()

        for date_str in _RE_DATE.findall(text):
            if date_str not in seen:
                deadlines.append(date_str)
                seen.add(date_str)

        for days_str in _RE_DAYS.findall(text):
            normalised = days_str.strip()
            if normalised not in seen:
                deadlines.append(normalised)
                seen.add(normalised)

        return deadlines

    @staticmethod
    def _extract_other_urls(
        text: str, onion_urls: list[str]
    ) -> list[str]:
        """Extract non-onion URLs from *text*.

        Parameters
        ----------
        text:
            Raw ransom note content.
        onion_urls:
            Already-extracted onion URLs to exclude from results.

        Returns
        -------
        list[str]
            Deduplicated non-onion URLs.
        """
        onion_set = {u.lower() for u in onion_urls}
        urls: list[str] = []
        seen: set[str] = set()

        for url in _RE_URL.findall(text):
            lower = url.lower()
            if ".onion" not in lower and lower not in seen and lower not in onion_set:
                urls.append(url)
                seen.add(lower)

        return urls
