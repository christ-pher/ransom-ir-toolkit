"""White Rabbit PE binary analyzer -- optional static analysis.

Performs static analysis on suspected White Rabbit ransomware PE binaries
to extract metadata, embedded IOCs, cryptographic key material, and
behavioural indicators.  White Rabbit samples are notable for requiring
a command-line password to decrypt and execute their payload.

Requires the ``pefile`` library for PE parsing.  All ``pefile`` imports
are wrapped in try/except so the module can be imported even when the
library is not installed; in that case :meth:`BinaryAnalyzer.analyze`
returns ``None`` with a logged warning.

Designed for Python 3.10+.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from tools.common.report import format_bytes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants and patterns
# ---------------------------------------------------------------------------

# Minimum length for extracted ASCII strings.
_MIN_STRING_LENGTH = 8

# Regex patterns for interesting strings inside binaries.
_RE_URL = re.compile(rb"https?://[^\x00-\x1f\x7f-\xff]{8,}")
_RE_IP = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    rb"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_FILE_PATH = re.compile(rb"[A-Z]:\\[^\x00-\x1f\x7f-\xff]{4,}")
_RE_REGISTRY = re.compile(
    rb"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\[^\x00-\x1f\x7f-\xff]{4,}"
)
_RE_CRYPTO_STRINGS = re.compile(
    rb"(?:AES|RSA|ChaCha|Salsa|curve25519|ed25519|sha256|sha512"
    rb"|CryptEncrypt|CryptDecrypt|BCrypt|NCrypt)",
    re.IGNORECASE,
)

# PEM header patterns for embedded RSA keys.
_PEM_BEGIN = b"-----BEGIN PUBLIC KEY-----"
_PEM_BEGIN_RSA = b"-----BEGIN RSA PUBLIC KEY-----"
_PEM_END = b"-----END PUBLIC KEY-----"
_PEM_END_RSA = b"-----END RSA PUBLIC KEY-----"

# ASN.1 DER sequence header for RSA public keys (30 82 xx xx ... 02 82).
_DER_RSA_PREFIX = b"\x30\x82"
_DER_RSA_INT = b"\x02\x82"

# Command-line password indicators (White Rabbit specific).
_PASSWORD_INDICATORS: list[bytes] = [
    b"-p",
    b"--password",
    b"passwd",
    b"-pass",
    b"/password",
]

# Section entropy threshold -- sections above this are likely packed or
# encrypted.
_HIGH_ENTROPY_THRESHOLD = 7.0


# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------

@dataclass
class BinaryAnalysis:
    """Results of static analysis on a PE binary.

    Attributes
    ----------
    file_path:
        Path to the analysed binary.
    file_size:
        Size in bytes.
    sha256:
        SHA-256 hash of the file contents.
    md5:
        MD5 hash of the file contents.
    imphash:
        Import hash (``pefile`` imphash), or ``None`` if unavailable.
    compile_timestamp:
        PE compilation timestamp string, or ``None``.
    sections:
        List of PE section metadata dicts with keys ``name``,
        ``virtual_size``, ``raw_size``, and ``entropy``.
    imports:
        Names of imported DLLs.
    embedded_strings:
        Interesting strings extracted from the binary (URLs, IPs,
        file paths, registry keys, crypto-related strings).
    embedded_rsa_pubkey:
        PEM-encoded RSA public key if found in the binary, else ``None``.
    is_packed:
        Heuristic flag: ``True`` if any section has entropy above the
        packing threshold.
    pdb_path:
        PDB debug path embedded in the binary, or ``None``.
    requires_password:
        ``True`` if command-line password indicators were found,
        suggesting White Rabbit's payload decryption mechanism.
    """

    file_path: Path
    file_size: int = 0
    sha256: str = ""
    md5: str = ""
    imphash: str | None = None
    compile_timestamp: str | None = None
    sections: list[dict] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    embedded_strings: list[str] = field(default_factory=list)
    embedded_rsa_pubkey: str | None = None
    is_packed: bool = False
    pdb_path: str | None = None
    requires_password: bool = False


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class BinaryAnalyzer:
    """Static analyser for suspected White Rabbit PE binaries.

    All analysis is performed without executing the sample.  The
    ``pefile`` library is required for PE header parsing; if it is not
    installed, :meth:`analyze` returns ``None`` with a warning.
    """

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, file_path: Path) -> BinaryAnalysis | None:
        """Perform full static analysis of a PE binary.

        Parameters
        ----------
        file_path:
            Path to the PE file to analyse.

        Returns
        -------
        BinaryAnalysis | None
            Analysis results, or ``None`` if ``pefile`` is not installed
            or the file cannot be parsed.
        """
        try:
            import pefile  # noqa: F811
        except ImportError:
            logger.warning(
                "pefile library is not installed. Install it with: "
                "pip install pefile"
            )
            return None

        file_path = Path(file_path)
        logger.info("Analysing PE binary: %s", file_path)

        try:
            raw_data = file_path.read_bytes()
        except OSError as exc:
            logger.error("Failed to read %s: %s", file_path, exc)
            return None

        sha256, md5 = self._calculate_hashes(raw_data)

        try:
            pe = pefile.PE(data=raw_data)
        except pefile.PEFormatError as exc:
            logger.error("Invalid PE file %s: %s", file_path, exc)
            return None

        # Import hash.
        imphash: str | None = None
        try:
            imphash = pe.get_imphash()
        except Exception:
            pass

        # Compilation timestamp.
        compile_timestamp: str | None = None
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts:
                from datetime import datetime, timezone

                compile_timestamp = datetime.fromtimestamp(
                    ts, tz=timezone.utc
                ).isoformat()
        except Exception:
            pass

        # Sections.
        sections: list[dict] = []
        is_packed = False
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode(
                "ascii", errors="replace"
            )
            entropy = section.get_entropy()
            sections.append({
                "name": name,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": round(entropy, 4),
            })
            if entropy > _HIGH_ENTROPY_THRESHOLD:
                is_packed = True

        # Imported DLLs.
        imports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode("ascii", errors="replace")
                imports.append(dll_name)

        # PDB path.
        pdb_path: str | None = None
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(debug_entry, "entry") and hasattr(
                    debug_entry.entry, "PdbFileName"
                ):
                    pdb_path = debug_entry.entry.PdbFileName.rstrip(
                        b"\x00"
                    ).decode("ascii", errors="replace")
                    break

        # Interesting strings.
        embedded_strings = self._extract_strings(raw_data, _MIN_STRING_LENGTH)

        # Embedded RSA public key.
        embedded_rsa_pubkey = self._find_rsa_key(raw_data)

        # Password requirement detection.
        requires_password = self._detect_password_requirement(raw_data)

        pe.close()

        analysis = BinaryAnalysis(
            file_path=file_path,
            file_size=len(raw_data),
            sha256=sha256,
            md5=md5,
            imphash=imphash,
            compile_timestamp=compile_timestamp,
            sections=sections,
            imports=imports,
            embedded_strings=embedded_strings,
            embedded_rsa_pubkey=embedded_rsa_pubkey,
            is_packed=is_packed,
            pdb_path=pdb_path,
            requires_password=requires_password,
        )

        logger.info(
            "Analysis complete: %s  sha256=%s  sections=%d  packed=%s  "
            "password_required=%s",
            file_path.name,
            sha256[:16] + "...",
            len(sections),
            is_packed,
            requires_password,
        )
        return analysis

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_hashes(data: bytes) -> tuple[str, str]:
        """Compute SHA-256 and MD5 hashes of raw file data.

        Parameters
        ----------
        data:
            Raw binary content.

        Returns
        -------
        tuple[str, str]
            ``(sha256_hex, md5_hex)``.
        """
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()  # noqa: S324
        return sha256, md5

    @staticmethod
    def _extract_strings(
        data: bytes, min_length: int = 8
    ) -> list[str]:
        """Extract interesting ASCII strings from binary data.

        Only strings matching patterns of operational significance are
        returned (URLs, IP addresses, file paths, registry keys, and
        crypto-related identifiers).

        Parameters
        ----------
        data:
            Raw binary content.
        min_length:
            Minimum character count for a string to be considered.

        Returns
        -------
        list[str]
            Deduplicated list of interesting strings.
        """
        # Extract all ASCII runs.
        ascii_pattern = re.compile(
            rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
        )
        raw_strings = ascii_pattern.findall(data)

        interesting: list[str] = []
        seen: set[str] = set()

        for raw in raw_strings:
            # Check against interest patterns.
            is_interesting = False
            for pattern in (
                _RE_URL,
                _RE_IP,
                _RE_FILE_PATH,
                _RE_REGISTRY,
                _RE_CRYPTO_STRINGS,
            ):
                if pattern.search(raw):
                    is_interesting = True
                    break

            if is_interesting:
                decoded = raw.decode("ascii", errors="replace")
                if decoded not in seen:
                    interesting.append(decoded)
                    seen.add(decoded)

        return interesting

    @staticmethod
    def _find_rsa_key(data: bytes) -> str | None:
        """Search for an embedded RSA public key in binary data.

        Looks for PEM-encoded keys first, then falls back to detecting
        ASN.1 DER-encoded RSA key structures.

        Parameters
        ----------
        data:
            Raw binary content.

        Returns
        -------
        str | None
            PEM-encoded public key string, or ``None`` if not found.
        """
        # Try PEM-encoded keys first.
        for begin, end in (
            (_PEM_BEGIN, _PEM_END),
            (_PEM_BEGIN_RSA, _PEM_END_RSA),
        ):
            start_idx = data.find(begin)
            if start_idx != -1:
                end_idx = data.find(end, start_idx)
                if end_idx != -1:
                    pem_data = data[start_idx : end_idx + len(end)]
                    try:
                        return pem_data.decode("ascii")
                    except UnicodeDecodeError:
                        pass

        # Try ASN.1 DER-encoded RSA public key detection.
        # Look for the pattern: 30 82 XX XX ... 02 82 (SEQUENCE containing
        # an INTEGER, which is the modulus).
        offset = 0
        while True:
            idx = data.find(_DER_RSA_PREFIX, offset)
            if idx == -1:
                break

            # Read the sequence length (2 bytes after 30 82).
            if idx + 4 > len(data):
                break

            seq_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
            if seq_len < 128 or seq_len > 4096:
                offset = idx + 1
                continue

            # Check for INTEGER marker within the sequence.
            candidate = data[idx : idx + 4 + seq_len]
            if _DER_RSA_INT in candidate:
                # Wrap in PEM format.
                import base64

                b64 = base64.b64encode(candidate).decode("ascii")
                pem_lines = ["-----BEGIN PUBLIC KEY-----"]
                for i in range(0, len(b64), 64):
                    pem_lines.append(b64[i : i + 64])
                pem_lines.append("-----END PUBLIC KEY-----")
                return "\n".join(pem_lines)

            offset = idx + 1

        return None

    @staticmethod
    def _detect_password_requirement(data: bytes) -> bool:
        """Check if the binary requires a command-line password.

        White Rabbit samples typically require a password argument
        (e.g. ``-p <password>``) to decrypt and execute their payload.

        Parameters
        ----------
        data:
            Raw binary content.

        Returns
        -------
        bool
            ``True`` if password-related command-line indicators were
            found.
        """
        lower_data = data.lower()
        for indicator in _PASSWORD_INDICATORS:
            if indicator.lower() in lower_data:
                return True
        return False
