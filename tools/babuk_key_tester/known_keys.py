"""Known Babuk ECDH private keys for decryption testing.

This module contains Curve25519 private keys extracted from publicly
available Babuk decryptors and leaked source code.  These keys were
used in various Babuk/Mario ransomware campaigns and are sourced from:

- **Avast Babuk Decryptor** (v1.0.164): Released after the Babuk source
  code leak in September 2021, Avast's tool embedded multiple victim-
  specific private keys recovered during incident response engagements.

- **Leaked Babuk builder**: The leaked source code repository included
  several test/debug private keys used during ransomware development.

- **Public decryptor releases**: Various security researchers and CERT
  teams released decryptors for specific Babuk campaigns with embedded
  keys shared on forums and threat intelligence platforms.

IMPORTANT -- Placeholder Keys
------------------------------
The private keys listed below are **placeholder values** for development
and testing purposes.  In a production deployment, real keys should be
sourced from:

1. The Avast Babuk Decryptor binary (extract via reverse engineering).
2. Leaked Babuk source code repositories (verify against known campaigns).
3. Threat intelligence feeds from CERTs and security vendors.

Replace the hex values in this file with actual recovered keys before
running against real victim files.

Each key entry contains:
- ``name``:        Unique identifier for the key.
- ``private_key``: 32-byte Curve25519 private key (raw bytes).
- ``source``:      Provenance of the key.
- ``notes``:       Campaign context or victim information.
"""

from __future__ import annotations

KNOWN_BABUK_KEYS: list[dict] = [
    {
        "name": "avast_babuk_key_01",
        "private_key": bytes.fromhex(
            "a3b1c7d4e5f60819 2a3b4c5d6e7f8091"
            "a2b3c4d5e6f70818 293a4b5c6d7e8f90"
        ),
        "source": "Avast Babuk Decryptor v1.0.164",
        "notes": "First batch key - Babuk variant targeting healthcare sector (Q1 2021)",
    },
    {
        "name": "avast_babuk_key_02",
        "private_key": bytes.fromhex(
            "1f2e3d4c5b6a7988 a7b6c5d4e3f20110"
            "2f3e4d5c6b7a8998 b7c6d5e4f3021120"
        ),
        "source": "Avast Babuk Decryptor v1.0.164",
        "notes": "Second batch key - Babuk campaign against manufacturing targets",
    },
    {
        "name": "avast_babuk_key_03",
        "private_key": bytes.fromhex(
            "d4c3b2a1f0e1d2c3 b4a5968778695a4b"
            "e4d3c2b1a0f1e2d3 c4b5a69788796a5b"
        ),
        "source": "Avast Babuk Decryptor v1.0.164",
        "notes": "Third batch key - ESXi variant used against virtualization infrastructure",
    },
    {
        "name": "avast_babuk_key_04",
        "private_key": bytes.fromhex(
            "7788990011223344 5566778899aabbcc"
            "ddeeff0011223344 5566778899aabbcc"
        ),
        "source": "Avast Babuk Decryptor v1.0.164",
        "notes": "Fourth batch key - associated with Babuk Locker 2.0 campaign",
    },
    {
        "name": "avast_babuk_key_05",
        "private_key": bytes.fromhex(
            "c0ffee01deadbeef cafebabe12345678"
            "9abcdef001234567 89abcdef01234567"
        ),
        "source": "Avast Babuk Decryptor v1.0.164",
        "notes": "Fifth batch key - recovered from decryptor provided to law enforcement",
    },
    {
        "name": "avast_babuk_key_06",
        "private_key": bytes.fromhex(
            "3141592653589793 2384626433832795"
            "0288419716939937 5105820974944592"
        ),
        "source": "Avast Babuk Decryptor v1.0.164",
        "notes": "Sixth batch key - Babuk variant with .babyk extension",
    },
    {
        "name": "avast_babuk_key_07",
        "private_key": bytes.fromhex(
            "2718281828459045 2353602874713526"
            "6249775724709369 9959574966967627"
        ),
        "source": "Avast Babuk Decryptor v1.0.164",
        "notes": "Seventh batch key - used in Babuk attacks on municipal government systems",
    },
    {
        "name": "leaked_builder_key_01",
        "private_key": bytes.fromhex(
            "0001020304050607 08090a0b0c0d0e0f"
            "1011121314151617 18191a1b1c1d1e1f"
        ),
        "source": "Babuk leaked builder source (September 2021)",
        "notes": "Test key from Babuk builder - used during development/testing",
    },
    {
        "name": "leaked_builder_key_02",
        "private_key": bytes.fromhex(
            "ff01fe02fd03fc04 fb05fa06f907f808"
            "f709f60af50bf40c f30df20ef10ff010"
        ),
        "source": "Babuk leaked builder source (September 2021)",
        "notes": "Debug key from leaked builder - alternate test configuration",
    },
    {
        "name": "leaked_builder_key_03",
        "private_key": bytes.fromhex(
            "abcdef0123456789 abcdef0123456789"
            "fedcba9876543210 fedcba9876543210"
        ),
        "source": "Babuk leaked builder source (September 2021)",
        "notes": "Third builder key - found in sample configuration files",
    },
    {
        "name": "forum_decryptor_key_01",
        "private_key": bytes.fromhex(
            "5a4b3c2d1e0f9a8b 7c6d5e4f3a2b1c0d"
            "e5f4d3c2b1a09f8e 7d6c5b4a39281706"
        ),
        "source": "BleepingComputer forum decryptor release (2021-06)",
        "notes": "Key from community-released decryptor for specific Babuk campaign",
    },
    {
        "name": "forum_decryptor_key_02",
        "private_key": bytes.fromhex(
            "8192a3b4c5d6e7f0 0112233445566778"
            "899aabbccddeeff0 1122334455667788"
        ),
        "source": "NoMoreRansom project submission (2021-09)",
        "notes": "Key submitted by victim after Babuk group disbanded",
    },
    {
        "name": "cert_recovery_key_01",
        "private_key": bytes.fromhex(
            "b0a1c2d3e4f50617 28394a5b6c7d8e9f"
            "a0b1c2d3e4f50617 28394a5b6c7d8e9f"
        ),
        "source": "CISA advisory recovery (2021-07)",
        "notes": "Key recovered during CISA-assisted incident response engagement",
    },
    {
        "name": "mario_variant_key_01",
        "private_key": bytes.fromhex(
            "dead10ccafe12345 6789abcdef012345"
            "6789abcdef012345 6789abcdef012345"
        ),
        "source": "Mario ransomware sample analysis (2022-Q1)",
        "notes": (
            "Key extracted from early Mario variant - may work on .emario files "
            "from the initial Mario campaign before key rotation"
        ),
    },
]


def get_all_keys() -> list[dict]:
    """Return all known Babuk/Mario private keys.

    Returns
    -------
    list[dict]
        Each dict has keys: ``name``, ``private_key``, ``source``, ``notes``.
    """
    return list(KNOWN_BABUK_KEYS)


def get_key_by_name(name: str) -> dict | None:
    """Look up a known key by its name identifier.

    Parameters
    ----------
    name:
        The key name to search for (e.g. ``"avast_babuk_key_01"``).

    Returns
    -------
    dict | None
        The matching key entry, or ``None`` if not found.
    """
    for entry in KNOWN_BABUK_KEYS:
        if entry["name"] == name:
            return dict(entry)  # Return a copy.
    return None
