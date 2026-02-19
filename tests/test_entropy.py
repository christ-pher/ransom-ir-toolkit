"""Tests for tools.common.entropy -- Shannon entropy calculation and classification.

Covers calculate_entropy, classify_entropy, EntropyResult, batch_entropy, and
the classification constants (ENCRYPTED, COMPRESSED, PLAINTEXT, ZEROED).
"""

from __future__ import annotations

import math

import pytest

from tools.common.entropy import (
    COMPRESSED,
    ENCRYPTED,
    PLAINTEXT,
    ZEROED,
    EntropyResult,
    batch_entropy,
    calculate_entropy,
    classify_entropy,
)


# ---------------------------------------------------------------------------
# calculate_entropy
# ---------------------------------------------------------------------------


class TestCalculateEntropy:
    """Unit tests for the Shannon entropy calculation."""

    def test_entropy_zeros(self) -> None:
        """All-zero bytes should have entropy 0.0 (single symbol)."""
        data = b"\x00" * 1024
        assert calculate_entropy(data) == 0.0

    def test_entropy_single_byte(self) -> None:
        """Repeated single non-zero byte should have entropy 0.0."""
        data = b"\xAB" * 4096
        assert calculate_entropy(data) == 0.0

    def test_entropy_uniform(self) -> None:
        """A buffer with each of the 256 byte values exactly once should
        have the theoretical maximum entropy of 8.0 bits/byte."""
        data = bytes(range(256))
        result = calculate_entropy(data)
        assert result == pytest.approx(8.0, abs=1e-10)

    def test_entropy_binary(self) -> None:
        """Alternating 0x00/0xFF (two equally likely symbols) should yield
        entropy of 1.0 bits/byte (-2 * 0.5 * log2(0.5) = 1.0)."""
        data = bytes([0x00, 0xFF] * 512)
        result = calculate_entropy(data)
        assert result == pytest.approx(1.0, abs=1e-10)

    def test_entropy_empty(self) -> None:
        """Empty input should return 0.0 without raising."""
        assert calculate_entropy(b"") == 0.0

    def test_entropy_single_byte_buffer(self) -> None:
        """A single-byte buffer has only one symbol; entropy is 0.0."""
        assert calculate_entropy(b"\x42") == 0.0

    def test_entropy_random_is_high(self) -> None:
        """A large block of os.urandom should have entropy close to 8.0."""
        import os
        data = os.urandom(65536)
        result = calculate_entropy(data)
        assert result > 7.9, f"Random data entropy unexpectedly low: {result}"

    def test_entropy_english_text(self) -> None:
        """ASCII English text should have entropy well below 7.0."""
        text = (b"The quick brown fox jumps over the lazy dog. " * 100)
        result = calculate_entropy(text)
        assert 2.0 < result < 5.0, f"English text entropy: {result}"


# ---------------------------------------------------------------------------
# classify_entropy
# ---------------------------------------------------------------------------


class TestClassifyEntropy:
    """Unit tests for entropy classification into human-readable categories."""

    def test_classify_encrypted(self) -> None:
        """Values >= 7.9 should classify as 'encrypted'."""
        assert classify_entropy(7.9) == ENCRYPTED
        assert classify_entropy(7.95) == ENCRYPTED
        assert classify_entropy(8.0) == ENCRYPTED

    def test_classify_compressed(self) -> None:
        """Values in [7.0, 7.9) should classify as 'compressed'."""
        assert classify_entropy(7.0) == COMPRESSED
        assert classify_entropy(7.5) == COMPRESSED
        assert classify_entropy(7.89) == COMPRESSED

    def test_classify_plaintext(self) -> None:
        """Values in [1.0, 7.0) should classify as 'plaintext'."""
        assert classify_entropy(1.0) == PLAINTEXT
        assert classify_entropy(3.5) == PLAINTEXT
        assert classify_entropy(6.99) == PLAINTEXT

    def test_classify_zeroed(self) -> None:
        """Values below 1.0 should classify as 'zeroed'."""
        assert classify_entropy(0.0) == ZEROED
        assert classify_entropy(0.5) == ZEROED
        assert classify_entropy(0.99) == ZEROED

    def test_classify_custom_threshold(self) -> None:
        """A custom threshold should move the encrypted/compressed boundary."""
        # With threshold=7.5, a value of 7.6 is now encrypted (not compressed).
        assert classify_entropy(7.6, threshold=7.5) == ENCRYPTED
        # And 7.4 is compressed because it is >= 7.0 but < 7.5.
        assert classify_entropy(7.4, threshold=7.5) == COMPRESSED

    def test_classify_boundary_exactness(self) -> None:
        """Boundaries should be lower-inclusive for the higher category."""
        # Exactly 7.9 -> encrypted
        assert classify_entropy(7.9) == ENCRYPTED
        # Exactly 7.0 -> compressed
        assert classify_entropy(7.0) == COMPRESSED
        # Exactly 1.0 -> plaintext
        assert classify_entropy(1.0) == PLAINTEXT


# ---------------------------------------------------------------------------
# EntropyResult
# ---------------------------------------------------------------------------


class TestEntropyResult:
    """Unit tests for the EntropyResult frozen dataclass."""

    def test_entropy_result_creation(self) -> None:
        """EntropyResult should store offset, size, entropy, and classification."""
        result = EntropyResult(
            offset=0, size=4096, entropy=7.95, classification=ENCRYPTED
        )
        assert result.offset == 0
        assert result.size == 4096
        assert result.entropy == 7.95
        assert result.classification == ENCRYPTED

    def test_entropy_result_frozen(self) -> None:
        """EntropyResult should be immutable (frozen dataclass)."""
        result = EntropyResult(
            offset=0, size=1024, entropy=3.0, classification=PLAINTEXT
        )
        with pytest.raises(AttributeError):
            result.entropy = 5.0  # type: ignore[misc]

        with pytest.raises(AttributeError):
            result.classification = ENCRYPTED  # type: ignore[misc]

    def test_entropy_result_equality(self) -> None:
        """Two EntropyResults with identical fields should be equal."""
        a = EntropyResult(offset=0, size=512, entropy=0.0, classification=ZEROED)
        b = EntropyResult(offset=0, size=512, entropy=0.0, classification=ZEROED)
        assert a == b


# ---------------------------------------------------------------------------
# batch_entropy
# ---------------------------------------------------------------------------


class TestBatchEntropy:
    """Unit tests for batch entropy calculation over consecutive blocks."""

    def test_batch_entropy(self) -> None:
        """batch_entropy should split data into blocks and classify each."""
        # 512 zero bytes + 256 bytes of uniform distribution
        zeros = b"\x00" * 512
        uniform = bytes(range(256))
        data = zeros + uniform

        results = batch_entropy(data, block_size=256)

        # First two blocks (512 bytes of zeros / 256 each) -> zeroed.
        assert len(results) == 3
        assert results[0].offset == 0
        assert results[0].size == 256
        assert results[0].classification == ZEROED

        assert results[1].offset == 256
        assert results[1].size == 256
        assert results[1].classification == ZEROED

        # Third block: bytes(range(256)) -> entropy 8.0 -> encrypted.
        assert results[2].offset == 512
        assert results[2].size == 256
        assert results[2].entropy == pytest.approx(8.0, abs=1e-10)
        assert results[2].classification == ENCRYPTED

    def test_batch_entropy_single_block(self) -> None:
        """When block_size >= len(data), a single result should be returned."""
        data = b"\x00" * 100
        results = batch_entropy(data, block_size=1000)
        assert len(results) == 1
        assert results[0].offset == 0
        assert results[0].size == 100

    def test_batch_entropy_empty_data(self) -> None:
        """Empty data should produce an empty results list."""
        results = batch_entropy(b"", block_size=256)
        assert results == []

    def test_batch_entropy_invalid_block_size(self) -> None:
        """block_size <= 0 should raise ValueError."""
        with pytest.raises(ValueError, match="block_size must be positive"):
            batch_entropy(b"\x00" * 100, block_size=0)

        with pytest.raises(ValueError, match="block_size must be positive"):
            batch_entropy(b"\x00" * 100, block_size=-1)

    def test_batch_entropy_final_block_shorter(self) -> None:
        """The final block should be shorter when data is not evenly divisible."""
        data = b"\x00" * 1000
        results = batch_entropy(data, block_size=300)
        assert len(results) == 4  # 300 + 300 + 300 + 100
        assert results[-1].size == 100

    def test_batch_entropy_custom_threshold(self) -> None:
        """Custom threshold should be passed through to classify_entropy."""
        import os
        data = os.urandom(256)
        # With threshold=9.0, nothing can be classified as encrypted since
        # max entropy is 8.0.
        results = batch_entropy(data, block_size=256, threshold=9.0)
        assert len(results) == 1
        assert results[0].classification != ENCRYPTED


# ---------------------------------------------------------------------------
# Classification constants
# ---------------------------------------------------------------------------


class TestConstants:
    """Verify the string values of classification constants."""

    def test_encrypted_constant(self) -> None:
        assert ENCRYPTED == "encrypted"

    def test_compressed_constant(self) -> None:
        assert COMPRESSED == "compressed"

    def test_plaintext_constant(self) -> None:
        assert PLAINTEXT == "plaintext"

    def test_zeroed_constant(self) -> None:
        assert ZEROED == "zeroed"
