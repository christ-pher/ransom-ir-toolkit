"""Generate synthetic test fixtures for end-to-end ransomware IR toolkit testing.

Creates realistic-looking VMDK files, .emario encrypted files, and White Rabbit
ransom notes with embedded IOCs.  All data is synthetic -- no actual malware or
victim data is produced.

Usage:
    python -m tests.generate_test_data
    # or
    python tests/generate_test_data.py
"""

from __future__ import annotations

import os
import struct
import textwrap
import zlib
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BLOCK_SIZE: int = 4 * 1024 * 1024  # 4 MiB per region

# Well-known file signatures to embed inside plaintext regions so that the
# data-carving and file-signature modules have something to detect.
_EMBEDDED_SIGNATURES: list[tuple[str, bytes]] = [
    ("PDF",    b"%PDF-1.7 fake document content for testing\n"),
    ("JPEG",   b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 64),
    ("PNG",    b"\x89PNG\r\n\x1a\n" + b"\x00" * 64),
    ("SQLite", b"SQLite format 3\x00" + b"\x00" * 64),
    ("ZIP",    b"PK\x03\x04" + b"\x00" * 64),
    ("GZIP",   b"\x1f\x8b\x08\x00" + b"\x00" * 64),
]

# Babuk footer size (Curve25519 ephemeral public key).
_BABUK_KEY_SIZE: int = 32

# Campaign-level IOC strings shared across generated ransom notes.
_CAMPAIGN_EMAILS: list[str] = [
    "darkops_support@protonmail.com",
    "recovery_team@tutanota.com",
]
_CAMPAIGN_ONION: str = "http://wh1t3r4bb1tn3g0t14t10nz.onion/chat"
_CAMPAIGN_BTC: str = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
_CAMPAIGN_TOX: str = (
    "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
)

# ---------------------------------------------------------------------------
# VMDK generation
# ---------------------------------------------------------------------------


def generate_test_vmdk(output_dir: Path, size_mb: int = 64) -> list[Path]:
    """Create a fake VMDK flat file with alternating encrypted/plaintext regions.

    The generated file follows a repeating pattern of 4 MiB blocks:
      1. Encrypted  -- random bytes (high entropy ~8.0)
      2. Plaintext  -- repeated patterns with embedded file signatures
      3. Compressed -- zlib-compressed data
      4. Zeroed     -- null bytes

    A companion ``.vmdk`` descriptor file is also created.

    Parameters
    ----------
    output_dir:
        Directory to write the generated files into.
    size_mb:
        Approximate total size of the flat extent in megabytes.

    Returns
    -------
    list[Path]
        Paths to created files (descriptor + flat extent).
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    flat_path = output_dir / "test-vm-flat.vmdk"
    descriptor_path = output_dir / "test-vm.vmdk"

    total_bytes = size_mb * 1024 * 1024
    written = 0
    block_index = 0

    with open(flat_path, "wb") as f:
        while written < total_bytes:
            phase = block_index % 4
            remaining = total_bytes - written
            block = min(_BLOCK_SIZE, remaining)

            if phase == 0:
                # Encrypted region -- random bytes (high entropy).
                data = os.urandom(block)
            elif phase == 1:
                # Plaintext region -- repeated text pattern with embedded sigs.
                pattern = b"This is plaintext data used for testing the ransomware IR toolkit. " * 64
                data = bytearray()
                sig_idx = 0
                while len(data) < block:
                    if sig_idx < len(_EMBEDDED_SIGNATURES):
                        _name, sig_bytes = _EMBEDDED_SIGNATURES[sig_idx]
                        data.extend(sig_bytes)
                        sig_idx += 1
                    chunk = pattern[: block - len(data)]
                    if not chunk:
                        break
                    data.extend(chunk)
                data = bytes(data[:block])
            elif phase == 2:
                # Compressed region -- zlib compressed random-ish content.
                raw = os.urandom(block)
                compressed = zlib.compress(raw, level=6)
                # Pad or truncate to block size.
                if len(compressed) < block:
                    compressed += b"\x00" * (block - len(compressed))
                data = compressed[:block]
            else:
                # Zeroed region.
                data = b"\x00" * block

            f.write(data)
            written += len(data)
            block_index += 1

    # Write a companion VMDK descriptor.
    total_sectors = written // 512
    descriptor_text = textwrap.dedent(f"""\
        # Disk DescriptorFile
        version=1
        CID=fffffffe
        parentCID=ffffffff
        createType="monolithicFlat"

        # Extent description
        RW {total_sectors} FLAT "test-vm-flat.vmdk" 0

        # The Disk Data Base
        #DDB
        ddb.virtualHWVersion = "21"
        ddb.geometry.cylinders = "130"
        ddb.geometry.heads = "16"
        ddb.geometry.sectors = "63"
        ddb.adapterType = "lsilogic"
    """)
    descriptor_path.write_text(descriptor_text, encoding="ascii")

    return [descriptor_path, flat_path]


# ---------------------------------------------------------------------------
# eMario file generation
# ---------------------------------------------------------------------------


def generate_test_emario(output_dir: Path, count: int = 5) -> list[Path]:
    """Create fake ``.emario`` files for header analysis testing.

    Each file contains a random data body (varying sizes) and a 32-byte
    Babuk-style footer representing the per-file Curve25519 public key.

    Parameters
    ----------
    output_dir:
        Directory to write generated files into.
    count:
        Number of ``.emario`` files to create.

    Returns
    -------
    list[Path]
        Paths to created ``.emario`` files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    sizes = [1024, 1024 * 1024, 10 * 1024 * 1024]  # 1 KB, 1 MB, 10 MB
    created: list[Path] = []

    for i in range(count):
        body_size = sizes[i % len(sizes)]
        filename = f"document_{i:03d}.docx.emario"
        path = output_dir / filename

        with open(path, "wb") as f:
            # Write random body (simulating encrypted content).
            remaining = body_size
            while remaining > 0:
                chunk = min(remaining, 1024 * 1024)
                f.write(os.urandom(chunk))
                remaining -= chunk

            # Append 32-byte Babuk footer (per-file ephemeral public key).
            footer = os.urandom(_BABUK_KEY_SIZE)
            f.write(footer)

        created.append(path)

    return created


# ---------------------------------------------------------------------------
# Ransom note generation
# ---------------------------------------------------------------------------


def generate_test_ransom_notes(output_dir: Path, count: int = 3) -> list[Path]:
    """Create fake White Rabbit ``.scrypt.txt`` ransom notes with realistic IOCs.

    Each note contains slightly different victim IDs but shares the same
    campaign-level contact information (emails, onion URLs, BTC addresses,
    TOX IDs).

    Parameters
    ----------
    output_dir:
        Directory to write generated notes into.
    count:
        Number of notes to create.

    Returns
    -------
    list[Path]
        Paths to created ransom note files.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []

    for i in range(count):
        victim_id = f"VIC-{os.urandom(4).hex().upper()}"
        deadline_days = 3 + i
        claimed_files = 12847 + i * 1000

        note_text = textwrap.dedent(f"""\
            ============================================================
             YOUR NETWORK HAS BEEN COMPROMISED - WHITE RABBIT RANSOMWARE
            ============================================================

            Your ID: {victim_id}

            All your files have been encrypted with military-grade encryption.
            We have also exfiltrated {claimed_files} files totaling 1.5 TB of
            sensitive data from your network including financial records,
            customer databases, and proprietary source code.

            DO NOT attempt to decrypt files yourself. DO NOT contact law
            enforcement. Any such actions will result in the permanent
            destruction of your decryption keys.

            To recover your files and prevent the public release of your
            data, contact us within {deadline_days} days using one of the
            following methods:

            Email:
              {_CAMPAIGN_EMAILS[0]}
              {_CAMPAIGN_EMAILS[1]}

            TOX Messenger (most secure):
              {_CAMPAIGN_TOX}

            Tor Negotiation Portal:
              {_CAMPAIGN_ONION}

            Bitcoin Payment Address:
              {_CAMPAIGN_BTC}

            After the deadline of {deadline_days} days, the price will double
            and we will begin publishing your data on our leak site.

            Proof of data exfiltration available upon request.

            -- White Rabbit Team
        """)

        filename = f"important_doc_{i:03d}.docx.scrypt.txt"
        path = output_dir / filename
        path.write_text(note_text, encoding="utf-8")
        created.append(path)

    return created


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Generate all test fixtures and print a summary."""
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    print(f"Generating test fixtures in: {fixtures_dir}")
    print("=" * 60)

    # VMDK files
    vmdk_dir = fixtures_dir / "vmdk"
    vmdk_files = generate_test_vmdk(vmdk_dir, size_mb=64)
    print(f"\nVMDK files ({len(vmdk_files)}):")
    for p in vmdk_files:
        size = p.stat().st_size
        print(f"  {p.name:40s}  {size:>12,} bytes")

    # eMario files
    emario_dir = fixtures_dir / "emario"
    emario_files = generate_test_emario(emario_dir, count=5)
    print(f"\neMario files ({len(emario_files)}):")
    for p in emario_files:
        size = p.stat().st_size
        print(f"  {p.name:40s}  {size:>12,} bytes")

    # Ransom notes
    notes_dir = fixtures_dir / "notes"
    note_files = generate_test_ransom_notes(notes_dir, count=3)
    print(f"\nRansom notes ({len(note_files)}):")
    for p in note_files:
        size = p.stat().st_size
        print(f"  {p.name:40s}  {size:>12,} bytes")

    # Summary
    total_files = len(vmdk_files) + len(emario_files) + len(note_files)
    print(f"\n{'=' * 60}")
    print(f"Total files created: {total_files}")
    print(f"Fixtures directory:  {fixtures_dir}")


if __name__ == "__main__":
    main()
