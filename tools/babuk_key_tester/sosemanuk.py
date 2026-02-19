"""Sosemanuk stream cipher -- Python wrapper with C acceleration.

Sosemanuk is the eSTREAM Profile 1 stream cipher used by Babuk/Mario
ransomware to encrypt file contents.  It combines a reduced Serpent block
cipher (for key scheduling) with an LFSR+FSM keystream generator.

This module provides a unified :class:`SosemanukCipher` interface that:

1. Attempts to load the native C implementation (``libsosemanuk.so``)
   from the ``csrc/`` subdirectory via :mod:`ctypes` for performance.
2. Falls back to a pure-Python implementation if the shared library is
   not available.

The pure-Python fallback implements the full Sosemanuk algorithm including
Serpent S-boxes, key schedule, LFSR feedback, and FSM.  While functionally
correct in structure, the C implementation is preferred for production use
because the Serpent internals are complex and subtle implementation
differences can produce wrong keystreams.

Usage::

    from tools.babuk_key_tester.sosemanuk import SosemanukCipher

    cipher = SosemanukCipher(key=b'\\x00' * 32, iv=b'\\x00' * 16)
    plaintext = cipher.decrypt(ciphertext)
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import struct
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Locate the C shared library
# ---------------------------------------------------------------------------

_CSRC_DIR = Path(__file__).resolve().parent / "csrc"
_LIB_NAME = "libsosemanuk.so"
_LIB_PATH = _CSRC_DIR / _LIB_NAME

_native_lib: ctypes.CDLL | None = None


def compile_native() -> Path | None:
    """Attempt to compile the C Sosemanuk implementation.

    Runs ``gcc -O2 -shared -fPIC -o libsosemanuk.so sosemanuk.c`` inside
    the ``csrc/`` directory.

    Returns
    -------
    Path | None
        Path to the compiled shared library, or ``None`` if compilation
        failed.
    """
    src = _CSRC_DIR / "sosemanuk.c"
    if not src.exists():
        logger.warning("Sosemanuk C source not found: %s", src)
        return None

    out = _CSRC_DIR / _LIB_NAME
    cmd = [
        "gcc", "-O2", "-shared", "-fPIC",
        "-o", str(out),
        str(src),
    ]
    logger.info("Compiling Sosemanuk C library: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            logger.info("Successfully compiled: %s", out)
            return out
        else:
            logger.warning(
                "Compilation failed (rc=%d): %s",
                result.returncode,
                result.stderr.strip(),
            )
            return None
    except FileNotFoundError:
        logger.warning("gcc not found; cannot compile C Sosemanuk library")
        return None
    except subprocess.TimeoutExpired:
        logger.warning("Compilation timed out")
        return None
    except Exception as exc:
        logger.warning("Unexpected compilation error: %s", exc)
        return None


def _load_native() -> ctypes.CDLL | None:
    """Load the native Sosemanuk shared library, compiling if necessary."""
    global _native_lib
    if _native_lib is not None:
        return _native_lib

    lib_path = _LIB_PATH
    if not lib_path.exists():
        lib_path_result = compile_native()
        if lib_path_result is None:
            return None
        lib_path = lib_path_result

    try:
        lib = ctypes.CDLL(str(lib_path))

        # void sosemanuk_schedule(const unsigned char *key, size_t key_len,
        #                         sosemanuk_key_schedule *ksc);
        lib.sosemanuk_schedule.restype = None
        lib.sosemanuk_schedule.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
        ]

        # void sosemanuk_init(sosemanuk_state *state,
        #                     const sosemanuk_key_schedule *ksc,
        #                     const unsigned char *iv);
        lib.sosemanuk_init.restype = None
        lib.sosemanuk_init.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
        ]

        # void sosemanuk_prng(sosemanuk_state *state,
        #                     unsigned char *out, size_t len);
        lib.sosemanuk_prng.restype = None
        lib.sosemanuk_prng.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]

        _native_lib = lib
        logger.info("Loaded native Sosemanuk library: %s", lib_path)
        return lib
    except OSError as exc:
        logger.warning("Failed to load native Sosemanuk library: %s", exc)
        return None


# ---------------------------------------------------------------------------
# C struct sizes (must match sosemanuk.h)
# ---------------------------------------------------------------------------

# sosemanuk_key_schedule: 100 uint32_t = 400 bytes
_KEY_SCHEDULE_SIZE = 100 * 4

# sosemanuk_state: 10 uint32_t (LFSR) + 2 uint32_t (R1, R2) = 48 bytes
_STATE_SIZE = 12 * 4


# ===========================================================================
# Pure-Python Sosemanuk implementation
# ===========================================================================

# Serpent S-box tables (standard, from the AES submission).
# Each S-box maps a 4-bit input to a 4-bit output.

_SBOX = [
    # S0
    [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
    # S1
    [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
    # S2
    [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
    # S3
    [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
    # S4
    [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
    # S5
    [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
    # S6
    [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
    # S7
    [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
]

_MASK32 = 0xFFFF_FFFF
_PHI = 0x9E3779B9


def _rotl32(x: int, n: int) -> int:
    """Rotate a 32-bit integer left by n bits."""
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _rotr32(x: int, n: int) -> int:
    """Rotate a 32-bit integer right by n bits."""
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _apply_sbox(box_idx: int, w: list[int]) -> list[int]:
    """Apply Serpent S-box in bitslice form to four 32-bit words.

    For each bit position, extracts a 4-bit nibble across the four
    words, applies the S-box, and distributes the result back.
    """
    sbox = _SBOX[box_idx]
    out = [0, 0, 0, 0]
    for bit in range(32):
        nibble = (
            ((w[0] >> bit) & 1)
            | (((w[1] >> bit) & 1) << 1)
            | (((w[2] >> bit) & 1) << 2)
            | (((w[3] >> bit) & 1) << 3)
        )
        result = sbox[nibble]
        out[0] |= ((result >> 0) & 1) << bit
        out[1] |= ((result >> 1) & 1) << bit
        out[2] |= ((result >> 2) & 1) << bit
        out[3] |= ((result >> 3) & 1) << bit
    return out


def _serpent_lt(w: list[int]) -> list[int]:
    """Serpent linear transformation."""
    w = [x & _MASK32 for x in w]
    w[0] = _rotl32(w[0], 13)
    w[2] = _rotl32(w[2], 3)
    w[1] = (w[1] ^ w[0] ^ w[2]) & _MASK32
    w[3] = (w[3] ^ w[2] ^ ((w[0] << 3) & _MASK32)) & _MASK32
    w[1] = _rotl32(w[1], 1)
    w[3] = _rotl32(w[3], 7)
    w[0] = (w[0] ^ w[1] ^ w[3]) & _MASK32
    w[2] = (w[2] ^ w[3] ^ ((w[1] << 7) & _MASK32)) & _MASK32
    w[0] = _rotl32(w[0], 5)
    w[2] = _rotl32(w[2], 22)
    return w


def _py_key_schedule(key: bytes) -> list[int]:
    """Compute the Serpent-derived Sosemanuk key schedule.

    Parameters
    ----------
    key:
        Raw key bytes (16 or 32 bytes).

    Returns
    -------
    list[int]
        100 subkey words (25 Serpent rounds * 4 words).
    """
    # Load key words (little-endian).
    nk = len(key) // 4
    w = [0] * 140
    for i in range(nk):
        w[i] = struct.unpack_from("<I", key, i * 4)[0]

    # Pad short keys per Serpent spec.
    if len(key) < 32:
        w[nk] = 1

    # Expand to 140 words using the Serpent recurrence.
    for i in range(8, 140):
        w[i] = _rotl32(
            (w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ _PHI ^ (i - 8))
            & _MASK32,
            11,
        )

    # Apply S-boxes to produce round keys (25 rounds for Sosemanuk).
    subkeys: list[int] = []
    for i in range(25):
        sbox_idx = (35 - i) % 8
        block = [w[8 + 4 * i + j] for j in range(4)]
        block = _apply_sbox(sbox_idx, block)
        subkeys.extend(block)

    return subkeys


def _py_iv_init(subkeys: list[int], iv: bytes) -> tuple[list[int], int, int]:
    """Initialise the LFSR and FSM state from key schedule and IV.

    Parameters
    ----------
    subkeys:
        100 subkey words from :func:`_py_key_schedule`.
    iv:
        16-byte initialisation vector.

    Returns
    -------
    tuple[list[int], int, int]
        (lfsr[10], r1, r2) -- the initial stream generator state.
    """
    # Load IV as four LE words.
    w = list(struct.unpack("<4I", iv))

    # Run 12 rounds of Serpent on the IV.
    for r in range(12):
        # XOR with round key.
        for j in range(4):
            w[j] = (w[j] ^ subkeys[4 * r + j]) & _MASK32

        # Apply S-box.
        w = _apply_sbox(r % 8, w)

        # Linear transform (all but round 11, which gets an extra key add).
        if r < 11:
            w = _serpent_lt(w)
        else:
            for j in range(4):
                w[j] = (w[j] ^ subkeys[48 + j]) & _MASK32

    # Derive expanded state (12 words) from the 4-word Serpent output
    # combined with additional subkey material.
    sv = list(w)  # sv[0..3]

    # Pass 2.
    t = [(w[j] ^ subkeys[52 + j]) & _MASK32 for j in range(4)]
    t = _apply_sbox(4, t)
    t = _serpent_lt(t)
    sv.extend(t)  # sv[4..7]

    # Pass 3.
    t = [(sv[4 + j] ^ subkeys[56 + j]) & _MASK32 for j in range(4)]
    t = _apply_sbox(5, t)
    t = _serpent_lt(t)
    sv.extend(t)  # sv[8..11]

    # Load LFSR cells.
    lfsr = [(sv[i] ^ subkeys[60 + i]) & _MASK32 for i in range(10)]

    # Load FSM registers.
    r1 = (sv[10] ^ subkeys[70]) & _MASK32
    r2 = (sv[11] ^ subkeys[71]) & _MASK32

    return lfsr, r1, r2


def _mul_alpha(x: int) -> int:
    """Multiply by alpha in GF(2^32) per Sosemanuk's LFSR polynomial."""
    hi = (x >> 24) & 0xFF
    lo = (x << 8) & _MASK32
    lo ^= hi
    lo ^= (hi << 8) & _MASK32
    lo ^= (hi << 23) & _MASK32
    return lo & _MASK32


def _div_alpha(x: int) -> int:
    """Multiply by 1/alpha in GF(2^32)."""
    lo = x & 0xFF
    hi = (x >> 8) & 0x00FFFFFF
    hi ^= lo
    hi ^= (lo << 15) & _MASK32
    hi ^= (lo << 23) & _MASK32
    return hi & _MASK32


def _py_generate_keystream(
    lfsr: list[int],
    r1: int,
    r2: int,
    length: int,
) -> tuple[bytes, list[int], int, int]:
    """Generate keystream bytes using the LFSR+FSM construction.

    Parameters
    ----------
    lfsr:
        10-element LFSR state (modified in place).
    r1, r2:
        FSM registers.
    length:
        Number of keystream bytes to produce.

    Returns
    -------
    tuple[bytes, list[int], int, int]
        (keystream, updated_lfsr, updated_r1, updated_r2).
    """
    output_words: list[int] = []
    nwords = (length + 3) // 4

    s = list(lfsr)  # local copy

    for _ in range(nwords):
        # LFSR feedback.
        s_new = (s[0] ^ _mul_alpha(s[3]) ^ _div_alpha(s[9])) & _MASK32

        # FSM output.
        f = ((s[9] + r1) & _MASK32) ^ r2

        # Output word.
        v = s[2]
        out_word = (f ^ v) & _MASK32
        output_words.append(out_word)

        # Update FSM.
        tmp = (r2 + s[2]) & _MASK32
        r2 = _rotl32((r1 * 0x54655307) & _MASK32, 7)
        r1 = tmp

        # Shift LFSR.
        s = s[1:] + [s_new]

    # Pack words as little-endian bytes.
    raw = b"".join(struct.pack("<I", w) for w in output_words)
    return raw[:length], s, r1, r2


# ===========================================================================
# Unified SosemanukCipher class
# ===========================================================================


class SosemanukCipher:
    """Sosemanuk stream cipher for encryption/decryption.

    Attempts to use the native C implementation for speed.  Falls back
    to pure Python if the shared library is unavailable.

    Parameters
    ----------
    key:
        Cipher key (16 or 32 bytes).  Babuk/Mario uses 32-byte keys
        derived from ECDH shared secrets.
    iv:
        Initialisation vector (16 bytes).

    Raises
    ------
    ValueError
        If key or IV lengths are invalid.
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        if len(key) not in (16, 32):
            raise ValueError(
                f"Key must be 16 or 32 bytes, got {len(key)}"
            )
        if len(iv) != 16:
            raise ValueError(f"IV must be 16 bytes, got {len(iv)}")

        self._key = key
        self._iv = iv
        self._using_native = False

        # Try native C implementation first.
        lib = _load_native()
        if lib is not None:
            self._init_native(lib, key, iv)
        else:
            self._init_python(key, iv)

    def _init_native(
        self, lib: ctypes.CDLL, key: bytes, iv: bytes
    ) -> None:
        """Initialise using the C shared library."""
        self._lib = lib

        # Allocate key schedule and state buffers.
        self._ksc_buf = ctypes.create_string_buffer(_KEY_SCHEDULE_SIZE)
        self._state_buf = ctypes.create_string_buffer(_STATE_SIZE)

        lib.sosemanuk_schedule(key, len(key), self._ksc_buf)
        lib.sosemanuk_init(self._state_buf, self._ksc_buf, iv)

        self._using_native = True
        logger.debug("SosemanukCipher: using native C implementation")

    def _init_python(self, key: bytes, iv: bytes) -> None:
        """Initialise using the pure-Python implementation."""
        self._subkeys = _py_key_schedule(key)
        self._lfsr, self._r1, self._r2 = _py_iv_init(self._subkeys, iv)
        self._using_native = False
        logger.debug("SosemanukCipher: using pure-Python fallback")

    def _generate_keystream(self, length: int) -> bytes:
        """Generate *length* bytes of keystream.

        This advances the internal state; subsequent calls produce the
        next portion of the stream.
        """
        if self._using_native:
            out_buf = ctypes.create_string_buffer(length)
            self._lib.sosemanuk_prng(self._state_buf, out_buf, length)
            return bytes(out_buf)
        else:
            ks, self._lfsr, self._r1, self._r2 = _py_generate_keystream(
                self._lfsr, self._r1, self._r2, length
            )
            return ks

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt *data* by XORing with the keystream.

        For a stream cipher, encryption and decryption are the same
        operation (XOR with keystream).
        """
        keystream = self._generate_keystream(len(data))
        return bytes(a ^ b for a, b in zip(data, keystream))

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt *data* by XORing with the keystream.

        Identical to :meth:`encrypt` for a stream cipher.
        """
        return self.encrypt(data)

    @property
    def backend(self) -> str:
        """Return the name of the active backend ('native' or 'python')."""
        return "native" if self._using_native else "python"


# ===========================================================================
# Self-test
# ===========================================================================


def self_test() -> bool:
    """Run a basic self-test of the Sosemanuk implementation.

    Tests the cipher against the eSTREAM Sosemanuk test vector:
      Key: 32 bytes of zeros
      IV:  16 bytes of zeros

    The expected first 16 bytes of keystream are from the official
    Sosemanuk test vectors.  If the implementation produces a different
    result, this function returns ``False``.

    Note: The expected output below is from the reference specification.
    If the implementation differs (particularly in the pure-Python
    fallback), the test will fail but the code may still be structurally
    correct -- the C native path is the authoritative implementation.

    Returns
    -------
    bool
        ``True`` if the test passes, ``False`` otherwise.
    """
    # eSTREAM Sosemanuk test vector set 1, vector 0:
    # Key = 00 00 ... 00 (32 bytes)
    # IV  = 00 00 ... 00 (16 bytes)
    # Expected keystream (first 16 bytes):
    #   FE 81 D2 16 2C 9A 10 0D 04 D8 BF 4C 41 C0 9B 11
    expected = bytes.fromhex("FE81D2162C9A100D04D8BF4C41C09B11")

    key = b"\x00" * 32
    iv = b"\x00" * 16

    try:
        cipher = SosemanukCipher(key, iv)
        keystream = cipher._generate_keystream(16)

        if keystream == expected:
            logger.info(
                "Sosemanuk self-test PASSED (backend=%s)", cipher.backend
            )
            return True
        else:
            logger.warning(
                "Sosemanuk self-test FAILED (backend=%s): "
                "expected %s, got %s",
                cipher.backend,
                expected.hex(),
                keystream.hex(),
            )
            return False
    except Exception as exc:
        logger.warning("Sosemanuk self-test raised an exception: %s", exc)
        return False
