"""Forensic-safe read-only I/O layer for ransomware incident response.

This module provides strictly read-only file access primitives designed
to protect forensic evidence integrity during ransomware analysis. All
file operations enforce O_RDONLY semantics and read-only memory mappings
so that evidence files (disk images, VMDK files, encrypted volumes) are
never modified, even accidentally.

Key guarantees:
    - Evidence files are opened exclusively with O_RDONLY / ACCESS_READ.
    - No write, append, or truncate operations are exposed.
    - Symlinks that resolve to block/character devices are rejected.
    - Output directories are validated to be outside the evidence tree.
    - Every file-access operation is logged for audit trail purposes.

Designed for Python 3.10+ with no external dependencies.
"""

from __future__ import annotations

import logging
import mmap
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_CHUNK_SIZE: int = 1 << 20  # 1 MiB


# ---------------------------------------------------------------------------
# Standalone validation helpers
# ---------------------------------------------------------------------------


def validate_evidence_path(path: str | os.PathLike[str]) -> Path:
    """Validate that *path* is a readable regular file suitable as evidence.

    Performs the following checks:
        1. The path exists on disk.
        2. The **resolved** path (after symlink resolution) points to a
           regular file -- not a block device, character device, FIFO,
           or socket.
        3. The current process has read permission.

    Parameters
    ----------
    path:
        Filesystem path to validate.

    Returns
    -------
    Path
        The fully-resolved :class:`pathlib.Path`.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    ValueError
        If *path* is not a regular file after symlink resolution, or if
        it is not readable.
    """
    p = Path(path)

    if not p.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {p}")

    resolved = p.resolve(strict=True)

    # Stat the *resolved* target so symlinks to devices are caught.
    st = resolved.stat()
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(
            f"Evidence path is not a regular file (mode "
            f"{stat.filemode(st.st_mode)}): {resolved}"
        )

    if not os.access(resolved, os.R_OK):
        raise ValueError(f"Evidence path is not readable: {resolved}")

    logger.info("Validated evidence path: %s (size=%d bytes)", resolved, st.st_size)
    return resolved


def ensure_output_dir(
    path: str | os.PathLike[str],
    evidence_path: Optional[str | os.PathLike[str]] = None,
) -> Path:
    """Create an output directory, ensuring it is not inside the evidence tree.

    Parameters
    ----------
    path:
        Desired output directory.  Created (with parents) if it does not
        already exist.
    evidence_path:
        Optional evidence file or directory.  When provided, the function
        verifies that *path* does not resolve to a location inside (or
        equal to) the evidence tree.

    Returns
    -------
    Path
        The resolved output directory path.

    Raises
    ------
    ValueError
        If the resolved output directory is inside the evidence path.
    OSError
        If the directory cannot be created.
    """
    out = Path(path).resolve()

    if evidence_path is not None:
        ev_root = Path(evidence_path).resolve()
        # If the evidence path is a file, guard its parent directory.
        if ev_root.is_file():
            ev_root = ev_root.parent

        # Check whether *out* is equal to or a child of the evidence tree.
        try:
            out.relative_to(ev_root)
        except ValueError:
            pass  # Good -- out is NOT inside ev_root.
        else:
            raise ValueError(
                f"Output directory {out} must not reside inside the "
                f"evidence tree ({ev_root})"
            )

    out.mkdir(parents=True, exist_ok=True)
    logger.info("Output directory ready: %s", out)
    return out


# ---------------------------------------------------------------------------
# SafeReader
# ---------------------------------------------------------------------------


class SafeReader:
    """Read-only file reader with memory-mapped access for forensic evidence.

    Opens the target file with :data:`os.O_RDONLY` and provides chunked
    reading, tail extraction, and region-specific memory mapping -- all
    without ever writing to the evidence file.

    Intended to handle very large files (100 GB+ VMDK images) efficiently
    by avoiding full-file reads and leveraging :mod:`mmap` for
    zero-copy access where possible.

    Usage::

        with SafeReader("/evidence/disk.vmdk") as reader:
            print(reader.get_size())
            for offset, chunk in reader.iter_chunks():
                process(chunk)
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path: Path = validate_evidence_path(path)
        self._fd: int = -1
        self._size: int = 0
        self._closed: bool = True

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> SafeReader:
        self._open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        self.close()

    # -- internal open / close ----------------------------------------------

    def _open(self) -> None:
        """Open the evidence file read-only via low-level OS descriptor."""
        if not self._closed:
            return
        self._fd = os.open(str(self._path), os.O_RDONLY)
        self._size = os.fstat(self._fd).st_size
        self._closed = False
        logger.info(
            "Opened evidence file (fd=%d): %s (%d bytes)",
            self._fd,
            self._path,
            self._size,
        )

    def close(self) -> None:
        """Close the underlying file descriptor if it is still open."""
        if self._closed:
            return
        os.close(self._fd)
        logger.info("Closed evidence file (fd=%d): %s", self._fd, self._path)
        self._fd = -1
        self._closed = True

    # -- helpers ------------------------------------------------------------

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("SafeReader is not open; use it as a context manager")

    # -- public API ---------------------------------------------------------

    @property
    def path(self) -> Path:
        """Return the resolved evidence file path."""
        return self._path

    def get_size(self) -> int:
        """Return the total size of the evidence file in bytes."""
        self._ensure_open()
        return self._size

    def read_chunk(self, offset: int, size: int) -> bytes:
        """Read *size* bytes starting at *offset*.

        Parameters
        ----------
        offset:
            Byte offset from the beginning of the file.  Must be >= 0.
        size:
            Maximum number of bytes to read.  The returned buffer may be
            shorter if the end of file is reached.

        Returns
        -------
        bytes
            The data read (may be shorter than *size* at EOF).

        Raises
        ------
        ValueError
            If *offset* or *size* is negative, or *offset* exceeds the
            file size.
        """
        self._ensure_open()

        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")
        if size < 0:
            raise ValueError(f"size must be >= 0, got {size}")
        if offset > self._size:
            raise ValueError(
                f"offset ({offset}) exceeds file size ({self._size})"
            )

        # Clamp to available data.
        actual_size = min(size, self._size - offset)
        if actual_size == 0:
            return b""

        data = os.pread(self._fd, actual_size, offset)
        logger.debug(
            "read_chunk: offset=%d requested=%d actual=%d file=%s",
            offset,
            size,
            len(data),
            self._path,
        )
        return data

    def iter_chunks(
        self, chunk_size: int = _DEFAULT_CHUNK_SIZE
    ) -> Iterator[tuple[int, bytes]]:
        """Iterate over the file in fixed-size chunks.

        Yields ``(offset, data)`` tuples.  The last chunk may be shorter
        than *chunk_size*.

        Parameters
        ----------
        chunk_size:
            Size of each chunk in bytes.  Defaults to 1 MiB.

        Yields
        ------
        tuple[int, bytes]
            ``(byte_offset, chunk_data)`` for each chunk.
        """
        self._ensure_open()

        if chunk_size <= 0:
            raise ValueError(f"chunk_size must be > 0, got {chunk_size}")

        offset = 0
        remaining = self._size
        logger.info(
            "iter_chunks: starting (chunk_size=%d, total=%d, file=%s)",
            chunk_size,
            self._size,
            self._path,
        )

        while remaining > 0:
            read_size = min(chunk_size, remaining)
            data = os.pread(self._fd, read_size, offset)
            if not data:
                break  # Unexpected EOF from the OS.
            yield offset, data
            offset += len(data)
            remaining -= len(data)

        logger.info("iter_chunks: completed (bytes_read=%d)", offset)

    def read_tail(self, size: int) -> bytes:
        """Read the last *size* bytes of the file.

        Useful for extracting key material appended to file footers
        (e.g., Babuk ransomware embeds the encrypted session key in the
        last portion of each encrypted file).

        Parameters
        ----------
        size:
            Number of bytes to read from the end of the file.  If
            *size* exceeds the file length the entire file is returned.

        Returns
        -------
        bytes
            The trailing bytes.
        """
        self._ensure_open()

        if size < 0:
            raise ValueError(f"size must be >= 0, got {size}")

        actual_size = min(size, self._size)
        if actual_size == 0:
            return b""

        offset = self._size - actual_size
        data = os.pread(self._fd, actual_size, offset)
        logger.debug(
            "read_tail: size=%d offset=%d actual=%d file=%s",
            size,
            offset,
            len(data),
            self._path,
        )
        return data

    def mmap_region(self, offset: int, length: int) -> memoryview | bytes:
        """Memory-map a specific region of the file for efficient access.

        The region is mapped read-only using :const:`mmap.ACCESS_READ`.
        Because :mod:`mmap` requires page-aligned offsets, the method
        adjusts automatically and returns a :class:`memoryview` trimmed
        to the exact requested window.

        For zero-length requests, or when the requested range falls
        entirely beyond the file, an empty :class:`bytes` object is
        returned instead.

        Parameters
        ----------
        offset:
            Byte offset from the start of the file.
        length:
            Number of bytes to map.

        Returns
        -------
        memoryview | bytes
            A read-only :class:`memoryview` over the mapped region, or
            ``b""`` for degenerate cases.

        Raises
        ------
        ValueError
            If *offset* or *length* is negative.
        """
        self._ensure_open()

        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")
        if length < 0:
            raise ValueError(f"length must be >= 0, got {length}")

        # Clamp to file boundaries.
        if offset >= self._size or length == 0:
            return b""

        actual_length = min(length, self._size - offset)

        # mmap requires the offset to be a multiple of the allocation
        # granularity (page size).
        page_size = mmap.ALLOCATIONGRANULARITY
        aligned_offset = (offset // page_size) * page_size
        padding = offset - aligned_offset
        map_length = actual_length + padding

        mm = mmap.mmap(
            self._fd,
            map_length,
            access=mmap.ACCESS_READ,
            offset=aligned_offset,
        )

        logger.debug(
            "mmap_region: offset=%d length=%d aligned_offset=%d "
            "map_length=%d file=%s",
            offset,
            length,
            aligned_offset,
            map_length,
            self._path,
        )

        # Return a memoryview trimmed to the exact requested region.
        view = memoryview(mm)
        return view[padding : padding + actual_length]

    # -- repr ---------------------------------------------------------------

    def __repr__(self) -> str:
        state = "open" if not self._closed else "closed"
        return f"<SafeReader path={self._path!r} state={state}>"
