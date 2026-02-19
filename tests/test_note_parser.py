"""Tests for tools.white_rabbit_analyzer.note_parser -- ransom note IOC extraction.

Covers NoteParser (parse_file, parse_directory) and the RansomNote data class,
including extraction of emails, onion URLs, BTC addresses (legacy and bech32),
TOX IDs, victim IDs, and full-note parsing.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tools.white_rabbit_analyzer.note_parser import NoteParser, RansomNote


# ---------------------------------------------------------------------------
# Reusable sample note content
# ---------------------------------------------------------------------------

SAMPLE_NOTE = textwrap.dedent("""\
    ============================================================
     YOUR NETWORK HAS BEEN COMPROMISED - WHITE RABBIT RANSOMWARE
    ============================================================

    Your ID: VIC-8A3F2B1C

    All your files have been encrypted with military-grade encryption.
    We have also exfiltrated 12847 files totaling 1.5 TB of
    sensitive data from your network.

    Contact us within 3 days:

    Email:
      darkops_support@protonmail.com
      recovery_team@tutanota.com

    TOX Messenger (most secure):
      A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2

    Tor Negotiation Portal:
      http://wh1t3r4bb1tn3g0t14t10nz.onion/chat

    Bitcoin Payment Address:
      bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

    Legacy BTC Address:
      1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

    After the deadline of 3 days, the price will double.

    -- White Rabbit Team
""")

# A note with a bare onion domain (no http:// prefix).
NOTE_WITH_BARE_ONION = textwrap.dedent("""\
    Contact us at our portal: wh1t3r4bb1tn3g0t14t10nz.onion
    Your ID: VIC-DEADBEEF
""")

# A note with multiple BTC addresses.
NOTE_MULTIPLE_BTC = textwrap.dedent("""\
    Your ID: VIC-MULTI

    Pay to one of these addresses:
    bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
    3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
    1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
""")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def parser() -> NoteParser:
    """Return a fresh NoteParser instance."""
    return NoteParser()


@pytest.fixture
def sample_note_file(tmp_path: Path) -> Path:
    """Write the sample note to a temp file and return its path."""
    path = tmp_path / "encrypted_file.docx.scrypt.txt"
    path.write_text(SAMPLE_NOTE, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Email extraction
# ---------------------------------------------------------------------------


class TestParseEmail:
    """Tests for email address extraction from ransom notes."""

    def test_parse_email(self, parser: NoteParser, sample_note_file: Path) -> None:
        """Emails from suspicious domains should be extracted."""
        note = parser.parse_file(sample_note_file)
        assert "darkops_support@protonmail.com" in note.emails
        assert "recovery_team@tutanota.com" in note.emails

    def test_only_suspicious_domains(self, parser: NoteParser, tmp_path: Path) -> None:
        """Emails from non-suspicious domains should be filtered out."""
        text = "Contact admin@example.com or support@protonmail.com"
        path = tmp_path / "test.scrypt.txt"
        path.write_text(text, encoding="utf-8")

        note = parser.parse_file(path)
        assert "support@protonmail.com" in note.emails
        assert "admin@example.com" not in note.emails

    def test_deduplicated_emails(self, parser: NoteParser, tmp_path: Path) -> None:
        """Duplicate emails should appear only once."""
        text = "Email: x@protonmail.com\nAgain: x@protonmail.com\n"
        path = tmp_path / "dedup.scrypt.txt"
        path.write_text(text, encoding="utf-8")

        note = parser.parse_file(path)
        assert note.emails.count("x@protonmail.com") == 1


# ---------------------------------------------------------------------------
# Onion URL extraction
# ---------------------------------------------------------------------------


class TestParseOnionUrl:
    """Tests for .onion URL extraction."""

    def test_parse_onion_url(self, parser: NoteParser, sample_note_file: Path) -> None:
        """Full http://*.onion URLs should be extracted."""
        note = parser.parse_file(sample_note_file)
        assert any(".onion" in url for url in note.onion_urls)

    def test_bare_onion_domain(self, parser: NoteParser, tmp_path: Path) -> None:
        """Bare .onion domains (without http://) should also be captured."""
        path = tmp_path / "bare.scrypt.txt"
        path.write_text(NOTE_WITH_BARE_ONION, encoding="utf-8")

        note = parser.parse_file(path)
        assert any("wh1t3r4bb1tn3g0t14t10nz.onion" in url for url in note.onion_urls)


# ---------------------------------------------------------------------------
# BTC address extraction
# ---------------------------------------------------------------------------


class TestParseBtcAddresses:
    """Tests for Bitcoin address extraction (legacy and bech32)."""

    def test_parse_btc_legacy(self, parser: NoteParser, sample_note_file: Path) -> None:
        """Legacy BTC addresses starting with 1 or 3 should be extracted."""
        note = parser.parse_file(sample_note_file)
        legacy = [a for a in note.btc_addresses if a.startswith(("1", "3"))]
        assert len(legacy) >= 1
        assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in note.btc_addresses

    def test_parse_btc_bech32(self, parser: NoteParser, sample_note_file: Path) -> None:
        """Bech32 BTC addresses starting with bc1 should be extracted."""
        note = parser.parse_file(sample_note_file)
        bech32 = [a for a in note.btc_addresses if a.startswith("bc1")]
        assert len(bech32) >= 1
        assert "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" in note.btc_addresses

    def test_parse_multiple_btc(self, parser: NoteParser, tmp_path: Path) -> None:
        """Multiple BTC addresses in one note should all be extracted."""
        path = tmp_path / "multi_btc.scrypt.txt"
        path.write_text(NOTE_MULTIPLE_BTC, encoding="utf-8")

        note = parser.parse_file(path)
        assert len(note.btc_addresses) >= 3


# ---------------------------------------------------------------------------
# TOX ID extraction
# ---------------------------------------------------------------------------


class TestParseToxId:
    """Tests for TOX messenger ID extraction."""

    def test_parse_tox_id(self, parser: NoteParser, sample_note_file: Path) -> None:
        """76-character hex TOX IDs should be extracted."""
        note = parser.parse_file(sample_note_file)
        assert len(note.tox_ids) >= 1
        for tox_id in note.tox_ids:
            assert len(tox_id) == 76
            # Should be valid uppercase hex.
            assert all(c in "0123456789ABCDEF" for c in tox_id)

    def test_no_tox_in_empty_note(self, parser: NoteParser, tmp_path: Path) -> None:
        """A note without a TOX ID should have an empty tox_ids list."""
        path = tmp_path / "no_tox.scrypt.txt"
        path.write_text("Your ID: VIC-000\nNo TOX here.\n", encoding="utf-8")

        note = parser.parse_file(path)
        assert note.tox_ids == []


# ---------------------------------------------------------------------------
# Victim ID extraction
# ---------------------------------------------------------------------------


class TestParseVictimId:
    """Tests for victim/reference ID extraction."""

    def test_parse_victim_id(self, parser: NoteParser, sample_note_file: Path) -> None:
        """'Your ID: VIC-8A3F2B1C' should extract VIC-8A3F2B1C."""
        note = parser.parse_file(sample_note_file)
        assert note.victim_id == "VIC-8A3F2B1C"

    def test_victim_id_with_equals(self, parser: NoteParser, tmp_path: Path) -> None:
        """'Your ID= VIC-XYZ' pattern should also work."""
        text = "Your ID= VIC-EQUALS\n"
        path = tmp_path / "eq.scrypt.txt"
        path.write_text(text, encoding="utf-8")

        note = parser.parse_file(path)
        assert note.victim_id == "VIC-EQUALS"

    def test_no_victim_id(self, parser: NoteParser, tmp_path: Path) -> None:
        """A note without a victim ID should return None."""
        path = tmp_path / "noid.scrypt.txt"
        path.write_text("No identification here.\n", encoding="utf-8")

        note = parser.parse_file(path)
        assert note.victim_id is None

    def test_reference_id_pattern(self, parser: NoteParser, tmp_path: Path) -> None:
        """'Reference: REF-12345' should extract the reference ID."""
        text = "Reference: REF-12345\n"
        path = tmp_path / "ref.scrypt.txt"
        path.write_text(text, encoding="utf-8")

        note = parser.parse_file(path)
        assert note.victim_id == "REF-12345"


# ---------------------------------------------------------------------------
# Full note parsing
# ---------------------------------------------------------------------------


class TestParseFullNote:
    """End-to-end tests parsing a complete ransom note."""

    def test_parse_full_note(self, parser: NoteParser, sample_note_file: Path) -> None:
        """A complete sample note should have all IOC types extracted."""
        note = parser.parse_file(sample_note_file)

        assert isinstance(note, RansomNote)
        assert note.raw_text == SAMPLE_NOTE
        assert note.file_path == sample_note_file

        # Victim ID.
        assert note.victim_id == "VIC-8A3F2B1C"

        # Emails.
        assert len(note.emails) >= 2
        assert "darkops_support@protonmail.com" in note.emails

        # Onion URLs.
        assert len(note.onion_urls) >= 1

        # BTC addresses.
        assert len(note.btc_addresses) >= 2

        # TOX IDs.
        assert len(note.tox_ids) >= 1

        # IOCs dict should consolidate everything.
        assert "email" in note.iocs
        assert "btc_address" in note.iocs
        assert "tox_id" in note.iocs

    def test_claimed_file_count(self, parser: NoteParser, sample_note_file: Path) -> None:
        """The claimed file count should be extracted from the note."""
        note = parser.parse_file(sample_note_file)
        assert note.claimed_file_count == 12847

    def test_claimed_data_size(self, parser: NoteParser, sample_note_file: Path) -> None:
        """The claimed data size should be extracted from the note."""
        note = parser.parse_file(sample_note_file)
        assert note.claimed_data_size is not None
        assert "TB" in note.claimed_data_size

    def test_deadlines_extracted(self, parser: NoteParser, sample_note_file: Path) -> None:
        """Deadline phrases ('3 days') should be extracted."""
        note = parser.parse_file(sample_note_file)
        assert len(note.deadlines) >= 1
        assert any("days" in d.lower() for d in note.deadlines)


# ---------------------------------------------------------------------------
# Directory parsing
# ---------------------------------------------------------------------------


class TestParseDirectory:
    """Tests for batch parsing of ransom notes in a directory."""

    def test_parse_directory(self, parser: NoteParser, tmp_path: Path) -> None:
        """parse_directory should find and parse all matching note files."""
        # Create several notes with the .scrypt.txt pattern.
        for i in range(3):
            path = tmp_path / f"file_{i}.docx.scrypt.txt"
            note_text = SAMPLE_NOTE.replace("VIC-8A3F2B1C", f"VIC-{i:08X}")
            path.write_text(note_text, encoding="utf-8")

        # Also create a non-matching file that should be ignored.
        (tmp_path / "regular.txt").write_text("not a ransom note")

        notes = parser.parse_directory(tmp_path)
        assert len(notes) == 3

        # Each note should have a unique victim ID.
        victim_ids = {n.victim_id for n in notes}
        assert len(victim_ids) == 3

    def test_parse_directory_nested(self, parser: NoteParser, tmp_path: Path) -> None:
        """Notes in subdirectories should be found recursively."""
        subdir = tmp_path / "level1" / "level2"
        subdir.mkdir(parents=True)

        path = subdir / "deep.scrypt.txt"
        path.write_text(SAMPLE_NOTE, encoding="utf-8")

        notes = parser.parse_directory(tmp_path)
        assert len(notes) >= 1

    def test_parse_directory_readme_pattern(self, parser: NoteParser, tmp_path: Path) -> None:
        """Files matching *README*.txt should also be picked up."""
        path = tmp_path / "README_DECRYPT.txt"
        path.write_text(SAMPLE_NOTE, encoding="utf-8")

        notes = parser.parse_directory(tmp_path)
        assert len(notes) >= 1

    def test_parse_directory_empty(self, parser: NoteParser, tmp_path: Path) -> None:
        """An empty directory should return an empty list."""
        notes = parser.parse_directory(tmp_path)
        assert notes == []

    def test_parse_directory_not_a_directory(
        self, parser: NoteParser, tmp_path: Path
    ) -> None:
        """Passing a file path should return an empty list (not crash)."""
        f = tmp_path / "file.txt"
        f.write_text("data")
        notes = parser.parse_directory(f)
        assert notes == []


# ---------------------------------------------------------------------------
# RansomNote dataclass
# ---------------------------------------------------------------------------


class TestRansomNote:
    """Tests for the RansomNote data container."""

    def test_default_fields(self) -> None:
        """A minimally-constructed RansomNote should have sensible defaults."""
        note = RansomNote(file_path=Path("/fake"), raw_text="test")
        assert note.victim_id is None
        assert note.emails == []
        assert note.onion_urls == []
        assert note.btc_addresses == []
        assert note.tox_ids == []
        assert note.deadlines == []
        assert note.claimed_file_count is None
        assert note.claimed_data_size is None
        assert note.other_urls == []
        assert note.iocs == {}

    def test_note_stores_raw_text(
        self, parser: NoteParser, sample_note_file: Path
    ) -> None:
        """The raw_text field should contain the original note content."""
        note = parser.parse_file(sample_note_file)
        assert note.raw_text == SAMPLE_NOTE
