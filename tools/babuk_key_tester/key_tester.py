"""Babuk/Mario key testing engine.

Performs X25519 ECDH key exchange with known Babuk private keys against
per-file ephemeral public keys extracted from Mario-encrypted files,
then attempts Sosemanuk decryption and validates the result.

The testing strategy:
    1. Extract the per-file Curve25519 public key from the file footer.
    2. For each known Babuk private key, compute the ECDH shared secret.
    3. Derive the Sosemanuk encryption key (SHA-256 of the shared secret).
    4. Attempt decryption of the first 512 bytes.
    5. Validate the decrypted output via entropy analysis, file signature
       matching, and ASCII-printable ratio.

This is a low-probability but zero-cost test: if any of the known keys
match, a file can be fully decrypted.

Usage::

    from tools.babuk_key_tester.key_tester import BabukKeyTester

    tester = BabukKeyTester()
    results = tester.test_file(Path("/evidence/file.emario"))
    for r in results:
        if r.success:
            print(f"MATCH: {r.key_name} (confidence={r.confidence:.0%})")
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tools.common.entropy import calculate_entropy, ENCRYPTED, PLAINTEXT
from tools.common.file_signatures import find_signature_at
from tools.common.safe_io import SafeReader

from tools.emario_header_analyzer.babuk_format import (
    BabukFooter,
    BABUK_KEY_SIZE,
    extract_babuk_footer,
    is_emario_file,
    find_emario_files,
)

from tools.babuk_key_tester.known_keys import get_all_keys
from tools.babuk_key_tester.sosemanuk import SosemanukCipher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Test configuration
# ---------------------------------------------------------------------------

_DECRYPT_TEST_SIZE: int = 512
"""Number of bytes to trial-decrypt for validation."""

_ENTROPY_SUCCESS_THRESHOLD: float = 6.0
"""Maximum entropy (bits/byte) for decrypted data to be considered
plausible plaintext.  Sosemanuk ciphertext has entropy near 8.0;
successful decryption should drop it well below this threshold for
typical files (documents, images, databases, etc.)."""

_ASCII_PRINTABLE_THRESHOLD: float = 0.6
"""Minimum ratio of ASCII-printable bytes (0x20..0x7E, plus common
whitespace) in the decrypted sample to suggest successful decryption
of a text-like file."""


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class TestResult:
    """Result of testing a single key against a single file.

    Attributes
    ----------
    file_path:
        Path to the encrypted file.
    key_name:
        Identifier of the key that was tested.
    key_hex:
        Hexadecimal representation of the tested private key.
    success:
        ``True`` if the decryption appears to have succeeded.
    confidence:
        Confidence score from 0.0 (no confidence) to 1.0 (certain match).
    decrypted_preview:
        First 512 bytes of decrypted data if the test was successful.
    signature_match:
        Name of the file type if a known magic signature was detected
        in the decrypted data.
    decrypted_entropy:
        Shannon entropy of the decrypted preview bytes.
    error:
        Error message if the test could not be performed.
    """

    file_path: Path
    key_name: str
    key_hex: str
    success: bool
    confidence: float
    decrypted_preview: bytes | None = None
    signature_match: str | None = None
    decrypted_entropy: float | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Key tester
# ---------------------------------------------------------------------------


class BabukKeyTester:
    """Test known Babuk private keys against Mario-encrypted files.

    Parameters
    ----------
    keys:
        Optional list of key dicts (each with ``name``, ``private_key``,
        ``source``, ``notes``).  If ``None``, loads the built-in known
        keys from :mod:`.known_keys`.
    """

    def __init__(self, keys: list[dict] | None = None) -> None:
        self._keys = keys if keys is not None else get_all_keys()
        logger.info("BabukKeyTester initialised with %d keys", len(self._keys))

    # -- Public API ---------------------------------------------------------

    def test_file(self, file_path: Path) -> list[TestResult]:
        """Test all known keys against a single encrypted file.

        Parameters
        ----------
        file_path:
            Path to a ``.emario`` / ``.omario`` file.

        Returns
        -------
        list[TestResult]
            One result per known key, ordered by confidence (descending).
        """
        file_path = Path(file_path)
        results: list[TestResult] = []

        # Extract the per-file public key from the footer.
        try:
            with SafeReader(file_path) as reader:
                footer = extract_babuk_footer(reader)
                file_size = reader.get_size()

                # Read the encrypted header (first N bytes after skipping
                # any format overhead -- Mario encrypts from offset 0).
                encrypted_header = reader.read_chunk(0, _DECRYPT_TEST_SIZE)
        except Exception as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            # Return error results for all keys.
            for key_entry in self._keys:
                results.append(TestResult(
                    file_path=file_path,
                    key_name=key_entry["name"],
                    key_hex=key_entry["private_key"].hex(),
                    success=False,
                    confidence=0.0,
                    error=f"File read error: {exc}",
                ))
            return results

        file_pubkey = footer.per_file_pubkey
        logger.info(
            "Testing %d keys against %s (pubkey=%s)",
            len(self._keys),
            file_path,
            footer.pubkey_hex,
        )

        for key_entry in self._keys:
            result = self._test_single_key(
                file_path=file_path,
                encrypted_header=encrypted_header,
                file_pubkey=file_pubkey,
                key_entry=key_entry,
            )
            results.append(result)

        # Sort by confidence descending.
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

    def test_directory(self, directory: Path) -> dict[str, list[TestResult]]:
        """Test all known keys against all ``.emario`` files in a directory.

        Parameters
        ----------
        directory:
            Root directory to scan recursively.

        Returns
        -------
        dict[str, list[TestResult]]
            Mapping from file path (as string) to the list of test
            results for that file.
        """
        directory = Path(directory)
        emario_files = find_emario_files(directory)
        logger.info(
            "Testing %d files in %s against %d keys",
            len(emario_files),
            directory,
            len(self._keys),
        )

        all_results: dict[str, list[TestResult]] = {}
        for file_path in emario_files:
            all_results[str(file_path)] = self.test_file(file_path)

        return all_results

    # -- Internal -----------------------------------------------------------

    def _test_single_key(
        self,
        file_path: Path,
        encrypted_header: bytes,
        file_pubkey: bytes,
        key_entry: dict,
    ) -> TestResult:
        """Test one key against one file's encrypted header.

        Performs X25519 ECDH, derives the Sosemanuk key, decrypts the
        header, and validates the result.
        """
        key_name = key_entry["name"]
        private_key_bytes = key_entry["private_key"]
        key_hex = private_key_bytes.hex()

        try:
            # 1. Perform X25519 ECDH to compute the shared secret.
            shared_secret = self._ecdh_exchange(private_key_bytes, file_pubkey)

            # 2. Derive Sosemanuk key: SHA-256 of the shared secret.
            sosemanuk_key = hashlib.sha256(shared_secret).digest()

            # 3. Try decryption with two IV strategies:
            #    a) IV = first 16 bytes of SHA-256(sosemanuk_key)
            #    b) IV = all zeros (some Babuk variants use this)
            iv_derived = hashlib.sha256(sosemanuk_key).digest()[:16]
            iv_zero = b"\x00" * 16

            best_result: TestResult | None = None

            for iv_label, iv in [("derived", iv_derived), ("zero", iv_zero)]:
                try:
                    cipher = SosemanukCipher(key=sosemanuk_key, iv=iv)
                    decrypted = cipher.decrypt(encrypted_header)

                    success, confidence, sig_name = self._validate_decryption(
                        decrypted
                    )
                    entropy = calculate_entropy(decrypted)

                    result = TestResult(
                        file_path=file_path,
                        key_name=key_name,
                        key_hex=key_hex,
                        success=success,
                        confidence=confidence,
                        decrypted_preview=decrypted if success else None,
                        signature_match=sig_name,
                        decrypted_entropy=entropy,
                    )

                    if best_result is None or confidence > best_result.confidence:
                        best_result = result

                    if success:
                        logger.warning(
                            "POTENTIAL MATCH: key=%s iv=%s file=%s "
                            "confidence=%.2f sig=%s entropy=%.4f",
                            key_name,
                            iv_label,
                            file_path,
                            confidence,
                            sig_name,
                            entropy,
                        )
                        return result  # Early exit on success.

                except Exception as exc:
                    logger.debug(
                        "Decryption error with key=%s iv=%s: %s",
                        key_name,
                        iv_label,
                        exc,
                    )
                    continue

            # Return the best non-successful result.
            if best_result is not None:
                return best_result

            return TestResult(
                file_path=file_path,
                key_name=key_name,
                key_hex=key_hex,
                success=False,
                confidence=0.0,
                error="All IV variants produced invalid decryption",
            )

        except Exception as exc:
            logger.debug("Key test failed: key=%s error=%s", key_name, exc)
            return TestResult(
                file_path=file_path,
                key_name=key_name,
                key_hex=key_hex,
                success=False,
                confidence=0.0,
                error=str(exc),
            )

    @staticmethod
    def _ecdh_exchange(
        private_key_bytes: bytes, public_key_bytes: bytes
    ) -> bytes:
        """Perform X25519 ECDH key exchange.

        Parameters
        ----------
        private_key_bytes:
            32-byte Curve25519 private key.
        public_key_bytes:
            32-byte Curve25519 public key (from the file footer).

        Returns
        -------
        bytes
            32-byte shared secret.

        Raises
        ------
        Exception
            If the cryptography library is not available or the key
            exchange fails.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import (
                X25519PrivateKey,
                X25519PublicKey,
            )
        except ImportError as exc:
            raise ImportError(
                "The 'cryptography' package is required for X25519 ECDH. "
                "Install it with: pip install cryptography"
            ) from exc

        private = X25519PrivateKey.from_private_bytes(private_key_bytes)
        public = X25519PublicKey.from_public_bytes(public_key_bytes)
        shared = private.exchange(public)
        return shared

    @staticmethod
    def _validate_decryption(
        plaintext: bytes,
    ) -> tuple[bool, float, str | None]:
        """Validate whether decrypted data looks like plausible plaintext.

        Uses three signals:
        1. **Entropy**: Successful decryption should produce data with
           significantly lower entropy than ciphertext (~8.0).
        2. **File signature**: If the decrypted data starts with a known
           magic sequence (PDF, ZIP, JPEG, etc.), this is strong evidence.
        3. **ASCII ratio**: A high proportion of printable ASCII bytes
           suggests a text-based file (documents, configs, scripts).

        Parameters
        ----------
        plaintext:
            Decrypted bytes to validate.

        Returns
        -------
        tuple[bool, float, str | None]
            ``(likely_success, confidence, matched_signature_name)``
        """
        if not plaintext:
            return False, 0.0, None

        confidence = 0.0
        sig_name: str | None = None

        # Signal 1: Entropy analysis.
        entropy = calculate_entropy(plaintext)

        if entropy < _ENTROPY_SUCCESS_THRESHOLD:
            # Low entropy is a positive signal.
            # The lower the entropy, the higher the confidence boost.
            entropy_score = max(0.0, (_ENTROPY_SUCCESS_THRESHOLD - entropy) / _ENTROPY_SUCCESS_THRESHOLD)
            confidence += entropy_score * 0.4  # Up to 0.4 from entropy.
        else:
            # High entropy -- almost certainly still ciphertext.
            # Still check for signatures in case of compressed data.
            pass

        # Signal 2: File signature detection.
        sig = find_signature_at(plaintext)
        if sig is not None:
            sig_name = sig.name
            confidence += 0.5  # Strong signal.

        # Signal 3: ASCII-printable ratio.
        printable_count = sum(
            1 for b in plaintext
            if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)  # tab, LF, CR
        )
        ascii_ratio = printable_count / len(plaintext) if plaintext else 0.0

        if ascii_ratio >= _ASCII_PRINTABLE_THRESHOLD:
            # High ASCII ratio -- likely a text file.
            confidence += ascii_ratio * 0.1  # Small boost, up to ~0.1.

        # Determine success.
        confidence = min(confidence, 1.0)
        success = confidence >= 0.3

        return success, confidence, sig_name
