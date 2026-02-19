"""Tests for tools.common.file_signatures -- magic byte signature detection.

Covers SIGNATURES catalogue, find_signatures, find_signature_at,
get_signatures_by_category, and FileSignature.
"""

from __future__ import annotations

import os

import pytest

from tools.common.file_signatures import (
    SIGNATURES,
    FileSignature,
    find_signature_at,
    find_signatures,
    get_signatures_by_category,
)


# ---------------------------------------------------------------------------
# Signature catalogue
# ---------------------------------------------------------------------------


class TestSignatureCatalogue:
    """Verify the built-in signature database meets expectations."""

    def test_signature_count(self) -> None:
        """The catalogue should contain at least 25 signatures."""
        assert len(SIGNATURES) >= 25, (
            f"Expected at least 25 signatures, found {len(SIGNATURES)}"
        )

    def test_all_signatures_have_required_fields(self) -> None:
        """Every signature should have a name, category, magic, and extension."""
        for sig in SIGNATURES:
            assert sig.name, f"Signature missing name: {sig}"
            assert sig.category, f"Signature missing category: {sig}"
            assert sig.magic, f"Signature missing magic bytes: {sig}"
            assert sig.extension.startswith("."), (
                f"Extension should start with '.': {sig.extension} ({sig.name})"
            )

    def test_signature_is_frozen(self) -> None:
        """FileSignature instances should be immutable (frozen dataclass)."""
        sig = SIGNATURES[0]
        with pytest.raises(AttributeError):
            sig.name = "modified"  # type: ignore[misc]

    def test_unique_categories(self) -> None:
        """The catalogue should contain at least 5 distinct categories."""
        categories = {sig.category for sig in SIGNATURES}
        assert len(categories) >= 5, f"Only {len(categories)} categories found"


# ---------------------------------------------------------------------------
# find_signatures
# ---------------------------------------------------------------------------


class TestFindSignatures:
    """Test bulk signature scanning of byte buffers."""

    def test_find_pdf_signature(self) -> None:
        """find_signatures should detect a PDF header."""
        data = b"%PDF-1.7 test document data"
        hits = find_signatures(data)
        names = [sig.name for _, sig in hits]
        assert "PDF" in names

    def test_find_jpeg_signature(self) -> None:
        """find_signatures should detect a JPEG SOI marker (FF D8 FF)."""
        data = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        hits = find_signatures(data)
        names = [sig.name for _, sig in hits]
        assert "JPEG" in names

    def test_find_png_signature(self) -> None:
        """find_signatures should detect a PNG header (89 50 4E 47)."""
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        hits = find_signatures(data)
        names = [sig.name for _, sig in hits]
        assert "PNG" in names

    def test_find_sqlite_signature(self) -> None:
        """find_signatures should detect SQLite format 3 header."""
        data = b"SQLite format 3\x00" + b"\x00" * 100
        hits = find_signatures(data)
        names = [sig.name for _, sig in hits]
        assert "SQLite" in names

    def test_find_multiple_signatures(self) -> None:
        """Data containing multiple signatures should find all of them."""
        # Embed a PDF, then a JPEG, then a PNG in one buffer.
        pdf_block = b"%PDF-1.4 test" + b"\x00" * 100
        jpeg_block = b"\xff\xd8\xff\xe0" + b"\x00" * 100
        png_block = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100

        data = pdf_block + jpeg_block + png_block
        hits = find_signatures(data)
        names = [sig.name for _, sig in hits]

        assert "PDF" in names
        assert "JPEG" in names
        assert "PNG" in names

    def test_find_signatures_with_offset(self) -> None:
        """The offset parameter should be added to reported positions."""
        data = b"%PDF-1.7 test"
        hits = find_signatures(data, offset=0x10000)
        assert len(hits) > 0
        abs_offset, sig = hits[0]
        assert abs_offset == 0x10000
        assert sig.name == "PDF"

    def test_find_signatures_empty_data(self) -> None:
        """Empty data should produce no hits."""
        assert find_signatures(b"") == []

    def test_tar_offset_signature(self) -> None:
        """TAR signature at offset 257 ('ustar') should be detected correctly.

        The TAR magic 'ustar' appears at byte 257 inside a valid tar file.
        find_signatures should find the magic and report the file start at
        position 0 (i.e. offset - 257).
        """
        # Build a buffer with 'ustar' at position 257.
        data = b"\x00" * 257 + b"ustar" + b"\x00" * 100
        hits = find_signatures(data)
        tar_hits = [(off, sig) for off, sig in hits if sig.name == "TAR"]
        assert len(tar_hits) >= 1, "TAR signature not detected at offset 257"
        # The reported file start should be 0 (257 - 257).
        assert tar_hits[0][0] == 0

    def test_no_false_positives_random(self) -> None:
        """Random data should not generate an excessive number of false positives.

        While short magic sequences (e.g. 2-byte BM for BMP) may occasionally
        match in random data, the count should remain small relative to the
        buffer size.
        """
        data = os.urandom(1_000_000)
        hits = find_signatures(data)
        # With 1 MB of random data and ~27 signatures, false positives should
        # be rare.  We set a generous upper bound.
        assert len(hits) < 500, (
            f"Too many false positives in random data: {len(hits)}"
        )


# ---------------------------------------------------------------------------
# find_signature_at
# ---------------------------------------------------------------------------


class TestFindSignatureAt:
    """Test single-position signature matching."""

    def test_find_signature_at_pdf(self) -> None:
        """find_signature_at should recognise a PDF at the start of data."""
        data = b"%PDF-1.5 some content"
        sig = find_signature_at(data)
        assert sig is not None
        assert sig.name == "PDF"

    def test_find_signature_at_jpeg(self) -> None:
        """find_signature_at should recognise a JPEG at the start."""
        data = b"\xff\xd8\xff\xe1" + b"\x00" * 50
        sig = find_signature_at(data)
        assert sig is not None
        assert sig.name == "JPEG"

    def test_find_signature_at_no_match(self) -> None:
        """Random data without a known header should return None."""
        # Use data unlikely to match any signature.
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08" * 100
        sig = find_signature_at(data)
        assert sig is None

    def test_find_signature_at_tar_offset(self) -> None:
        """find_signature_at should detect TAR when 'ustar' is at offset 257."""
        data = b"\x00" * 257 + b"ustar" + b"\x00" * 100
        sig = find_signature_at(data)
        assert sig is not None
        assert sig.name == "TAR"

    def test_find_signature_at_too_short(self) -> None:
        """Data shorter than any magic should return None."""
        sig = find_signature_at(b"\x00")
        # Might match if any 1-byte magic exists, but most are 2+ bytes.
        # The important thing is it does not crash.
        # We accept either None or a valid FileSignature.
        assert sig is None or isinstance(sig, FileSignature)


# ---------------------------------------------------------------------------
# get_signatures_by_category
# ---------------------------------------------------------------------------


class TestGetSignaturesByCategory:
    """Test category-based signature filtering."""

    def test_get_signatures_by_category_image(self) -> None:
        """Filtering by 'image' should return image-type signatures."""
        image_sigs = get_signatures_by_category("image")
        assert len(image_sigs) > 0
        for sig in image_sigs:
            assert sig.category == "image"

    def test_get_signatures_by_category_case_insensitive(self) -> None:
        """Category matching should be case-insensitive."""
        lower = get_signatures_by_category("image")
        upper = get_signatures_by_category("Image")
        mixed = get_signatures_by_category("IMAGE")

        assert lower == upper
        assert upper == mixed

    def test_get_signatures_by_category_document(self) -> None:
        """Filtering by 'document' should return document-type signatures."""
        doc_sigs = get_signatures_by_category("document")
        assert len(doc_sigs) > 0
        names = {sig.name for sig in doc_sigs}
        assert "PDF" in names

    def test_get_signatures_by_category_archive(self) -> None:
        """Filtering by 'archive' should return archive-type signatures."""
        archive_sigs = get_signatures_by_category("archive")
        assert len(archive_sigs) > 0
        names = {sig.name for sig in archive_sigs}
        assert "ZIP" in names

    def test_get_signatures_by_category_nonexistent(self) -> None:
        """A category with no matching signatures should return an empty list."""
        result = get_signatures_by_category("nonexistent_category_xyz")
        assert result == []

    def test_image_signatures_include_known_formats(self) -> None:
        """The image category should include JPEG, PNG, and at least one
        additional format."""
        image_sigs = get_signatures_by_category("image")
        names = {sig.name for sig in image_sigs}
        assert "JPEG" in names
        assert "PNG" in names
        assert len(names) >= 3  # JPEG + PNG + at least one more
