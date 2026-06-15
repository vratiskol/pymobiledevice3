import struct

import pytest

from pymobiledevice3.apple_compression import AppleCompressionError, decompress_bv41, decompress_lz4_raw


def test_decompress_lz4_raw_literal_only_block() -> None:
    assert decompress_lz4_raw(b"\x50hello", 5) == b"hello"


def test_decompress_lz4_raw_with_overlapping_match() -> None:
    assert decompress_lz4_raw(b"\x35abc\x03\x00", 12) == b"abcabcabcabc"


def test_decompress_bv41_ignores_apple_trailer_padding() -> None:
    compressed = b"\x35abc\x03\x00"
    payload = struct.pack("<4sII", b"bv41", 12, len(compressed)) + compressed + b"\x00\x00\x00\x00"

    assert decompress_bv41(payload) == b"abcabcabcabc"


def test_decompress_bv41_rejects_truncated_payload() -> None:
    payload = struct.pack("<4sII", b"bv41", 12, 16) + b"\x35abc\x03\x00"

    with pytest.raises(AppleCompressionError, match="truncated"):
        decompress_bv41(payload)
