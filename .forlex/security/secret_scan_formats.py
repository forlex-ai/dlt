"""Pure format/schema checks loaded only from the trusted scanner sibling path."""

import re
from datetime import datetime
from operator import is_
from pathlib import Path


def unsupported_archive(prefix, sources):
    """Refuse recognized archive/compressed blobs, including malformed headers.

    The pinned extractor silently skips some members. Inspect at most the first
    512 raw bytes and retained original names without decompressing or extracting.
    Signature-free Brotli and legacy TAR need name/header checks. This is a
    conservative refusal, never evidence that arbitrary encoded data was decoded.

    Returns:
        Whether this blob requires separate archive-content qualification.
    """
    extensions = {
        ".7z",
        ".zip",
        ".rar",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".tbz",
        ".tbz2",
        ".xz",
        ".txz",
        ".lz4",
        ".lz",
        ".tlz",
        ".zst",
        ".tzst",
        ".zz",
        ".zlib",
        ".br",
        ".sz",
        ".s2",
        ".z",
        ".ar",
        ".deb",
        ".rpm",
        ".apk",
        ".jar",
        ".whl",
    }
    if any(Path(source["file"]).suffix.lower() in extensions for source in sources):
        return True
    signatures = (
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07\x00",
        b"Rar!\x1a\x07\x01\x00",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ\x00",
        b"\x04\x22\x4d\x18",
        b"\x02\x21\x4c\x18",
        b"LZIP",
        b"\x28\xb5\x2f\xfd",
        b"\xff\x06\x00\x00sNaPpY",
        b"\xff\x06\x00\x00S2sTwO",
        b"!<arch>\n",
        b"\xed\xab\xee\xdb",
        b"070701",
        b"070702",
        b"070707",
        b"\x71\xc7",
        b"\xc7\x71",
        b"\x1f\x9d",
        b"MSCF",
        b"xar!",
    )
    if prefix.startswith(signatures) or prefix[257:262] == b"ustar":
        return True
    # Zstandard/LZ4 skippable frames can precede real frames.
    if len(prefix) >= 4 and 0x50 <= prefix[0] <= 0x5F and prefix[1:4] == b"\x2a\x4d\x18":
        return True
    # RFC 1950 DEFLATE headers, including dictionary-bearing variants, have a checksum.
    if (
        len(prefix) >= 2
        and prefix[0] & 15 == 8
        and prefix[0] >> 4 <= 7
        and int.from_bytes(prefix[:2], "big") % 31 == 0
    ):
        return True
    if len(prefix) >= 512:
        checksum = prefix[148:156].strip(b"\x00 ")
        if checksum and all(48 <= value <= 55 for value in checksum):
            expected = int(checksum, 8)
            data = prefix[:148] + b" " * 8 + prefix[156:512]
            # Legacy V7 TAR has no magic; accept both historic checksum conventions.
            if expected in {
                sum(data),
                sum(value if value < 128 else value - 256 for value in data),
            }:
                return True
    return False


def valid_lifecycle_diagnostic(row):
    """Accept only exact v3.99.2 offline filesystem lifecycle log schemas.

    No message is accepted by log level alone, including debug/info skip reports.
    Extra error fields, incomplete records and unrecognized messages are refused.

    Returns:
        Whether all fields match a known pinned lifecycle schema.
    """
    common = {"level", "ts", "logger", "msg"}
    if (
        not isinstance(row, dict)
        or row.get("level") != "info-0"
        or row.get("logger") != "trufflehog"
    ):
        return False
    stamp = row.get("ts")
    if not isinstance(stamp, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})",
        stamp,
    ):
        return False
    try:
        datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)
    except ValueError:
        return False
    if row.get("msg") == "running source":
        worker = row.get("source_manager_worker_id")
        return (
            set(row) == common | {"source_manager_worker_id", "with_units"}
            and row["with_units"] is True
            and isinstance(worker, str)
            and re.fullmatch(r"[A-Za-z0-9]{5}", worker) is not None
        )
    counts = {"chunks", "bytes", "verified_secrets", "unverified_secrets"}
    if row.get("msg") != "finished scanning" or set(row) != common | counts | {
        "scan_duration",
        "trufflehog_version",
        "verification_caching",
    }:
        return False
    if any(not is_(type(row[key]), int) or row[key] < 0 for key in counts):
        return False
    duration = row["scan_duration"]
    if (
        row["trufflehog_version"] != "3.99.2"
        or not isinstance(duration, str)
        or not re.fullmatch(
            r"(?:(?:[0-9]+h)?(?:[0-9]+m)?[0-9]+(?:\.[0-9]+)?s|[0-9]+(?:\.[0-9]+)?(?:ms|µs|ns))",
            duration,
        )
    ):
        return False
    cache = row["verification_caching"]
    return (
        isinstance(cache, dict)
        and set(cache)
        == {"Hits", "Misses", "HitsWasted", "AttemptsSaved", "VerificationTimeSpentMS"}
        and all(is_(type(value), int) and value >= 0 for value in cache.values())
    )
