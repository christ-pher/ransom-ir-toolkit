"""Shannon entropy calculation for ransomware incident response.

This module provides entropy-based classification of byte regions within
disk images (particularly VMDK files) to distinguish encrypted, compressed,
plaintext, and zeroed regions during Mario ransomware analysis.

Entropy Thresholds
------------------
The default threshold of 7.9 bits/byte is chosen to separate Sosemanuk
cipher output from ordinary compressed data:

- Sosemanuk (Mario's stream cipher) produces output with entropy very
  close to the theoretical maximum of 8.0 bits/byte, typically in the
  range [7.95, 8.0]. This is characteristic of strong stream ciphers
  whose output is computationally indistinguishable from random bytes.

- Compressed data (zlib, gzip, LZMA) generally falls in the range
  [7.0, 7.9). Compression removes redundancy but retains structure
  in headers, dictionaries, and block boundaries that pulls entropy
  below the theoretical maximum.

- Plaintext and structured binary data (filesystems, databases, logs)
  sit well below 7.0 due to byte-value skew and repetition.

- Zeroed or sparse regions have near-zero entropy.

A threshold of 7.9 therefore cleanly separates encrypted regions from
everything else in Mario-encrypted VMDK files, where the ransomware
applies intermittent/sparse encryption to selected regions.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Classification constants
# ---------------------------------------------------------------------------

ENCRYPTED: str = "encrypted"
COMPRESSED: str = "compressed"
PLAINTEXT: str = "plaintext"
ZEROED: str = "zeroed"

# Boundary values (lower-inclusive except where noted)
_THRESHOLD_ENCRYPTED: float = 7.9
_THRESHOLD_COMPRESSED: float = 7.0
_THRESHOLD_PLAINTEXT: float = 1.0


# ---------------------------------------------------------------------------
# Core entropy calculation
# ---------------------------------------------------------------------------

def calculate_entropy(data: bytes) -> float:
    """Return the Shannon entropy of *data* on a 0.0 -- 8.0 scale.

    Each byte is treated as an independent symbol drawn from a 256-value
    alphabet.  The returned value is in bits per byte:

    * 0.0  -- perfectly uniform (e.g. all zeros)
    * 8.0  -- theoretically maximum (each of 256 values equally likely)

    Parameters
    ----------
    data:
        Raw bytes to analyse.  An empty buffer returns 0.0.

    Returns
    -------
    float
        Shannon entropy in bits per byte.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_entropy(entropy_value: float, threshold: float = 7.9) -> str:
    """Classify an entropy value into a human-readable category.

    Parameters
    ----------
    entropy_value:
        Shannon entropy in bits/byte (0.0 -- 8.0).
    threshold:
        The boundary between *encrypted* and *compressed*.  Defaults to
        7.9, which reliably separates Sosemanuk cipher output (~8.0)
        from compressed data (~7.0 -- 7.8).  Adjust downward if the
        ransomware variant uses a weaker cipher or partial encryption
        that lowers observed entropy.

    Returns
    -------
    str
        One of ``"encrypted"``, ``"compressed"``, ``"plaintext"``, or
        ``"zeroed"``.
    """
    if entropy_value >= threshold:
        return ENCRYPTED
    if entropy_value >= _THRESHOLD_COMPRESSED:
        return COMPRESSED
    if entropy_value >= _THRESHOLD_PLAINTEXT:
        return PLAINTEXT
    return ZEROED


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class EntropyResult:
    """Entropy measurement for a single block within a larger buffer.

    Attributes
    ----------
    offset:
        Byte offset of the block relative to the start of the buffer
        passed to :func:`batch_entropy`.
    size:
        Length of the block in bytes (may be shorter than *block_size*
        for the final block).
    entropy:
        Shannon entropy of the block (0.0 -- 8.0).
    classification:
        Human-readable label produced by :func:`classify_entropy`.
    """

    offset: int
    size: int
    entropy: float
    classification: str


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def batch_entropy(
    data: bytes,
    block_size: int,
    threshold: float = 7.9,
) -> list[EntropyResult]:
    """Calculate per-block entropy for consecutive blocks in *data*.

    The buffer is divided into non-overlapping blocks of *block_size*
    bytes.  The final block may be shorter if ``len(data)`` is not an
    exact multiple of *block_size*.

    Parameters
    ----------
    data:
        Raw bytes to analyse.
    block_size:
        Size of each block in bytes.  Must be a positive integer.
    threshold:
        Passed through to :func:`classify_entropy` for each block.

    Returns
    -------
    list[EntropyResult]
        One :class:`EntropyResult` per block, in offset order.

    Raises
    ------
    ValueError
        If *block_size* is not a positive integer.
    """
    if block_size <= 0:
        raise ValueError(f"block_size must be positive, got {block_size}")

    results: list[EntropyResult] = []
    length = len(data)

    for offset in range(0, length, block_size):
        block = data[offset : offset + block_size]
        ent = calculate_entropy(block)
        results.append(
            EntropyResult(
                offset=offset,
                size=len(block),
                entropy=ent,
                classification=classify_entropy(ent, threshold),
            )
        )

    return results
