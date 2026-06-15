import ctypes
import ctypes.util
import platform
import struct
from typing import Optional

COMPRESSION_LZ4 = 0x100
COMPRESSION_LZVN = 0x800

APPLE_COMPRESSION_HEADER_SIZE = 12
APPLE_COMPRESSION_LZ4_MAGIC = b"bv41"


class AppleCompressionError(ValueError):
    pass


def decompress_apple_compression(payload: bytes) -> bytes:
    """Decode an Apple Compression buffer.

    The iOS tracev3 firehose chunks seen in sysdiagnose use the Apple
    Compression LZ4 wrapper:

        magic='bv41', uint32 uncompressed_size, uint32 compressed_size,
        compressed raw LZ4 block, optional 4-byte trailer/padding.

    `compression_decode_buffer(..., COMPRESSION_LZ4)` accepts the complete
    wrapper on Darwin. For Linux forensic parsing we decode the `bv41` wrapper
    directly and keep the Darwin fallback for other Apple Compression formats.
    """
    if payload.startswith(APPLE_COMPRESSION_LZ4_MAGIC):
        return decompress_bv41(payload)
    decoded = _decode_macos_compression(payload)
    if decoded is not None:
        return decoded
    raise AppleCompressionError("unsupported Apple Compression payload")


def decompress_bv41(payload: bytes) -> bytes:
    if len(payload) < APPLE_COMPRESSION_HEADER_SIZE:
        raise AppleCompressionError("truncated bv41 header")

    magic, uncompressed_size, compressed_size = struct.unpack_from("<4sII", payload)
    if magic != APPLE_COMPRESSION_LZ4_MAGIC:
        raise AppleCompressionError("not a bv41 Apple Compression LZ4 block")

    compressed_offset = APPLE_COMPRESSION_HEADER_SIZE
    compressed_end = compressed_offset + compressed_size
    if compressed_end > len(payload):
        raise AppleCompressionError("truncated bv41 compressed payload")

    compressed_payload = payload[compressed_offset:compressed_end]
    decoded = _decompress_lz4_raw_fast(compressed_payload, uncompressed_size)
    if decoded is not None:
        return decoded
    return decompress_lz4_raw(compressed_payload, uncompressed_size)


def decompress_lz4_raw(payload: bytes, uncompressed_size: int) -> bytes:
    if uncompressed_size < 0:
        raise AppleCompressionError("invalid LZ4 uncompressed size")

    output = bytearray()
    offset = 0
    payload_size = len(payload)

    while offset < payload_size:
        token = payload[offset]
        offset += 1

        literal_length, offset = _read_lz4_length(payload, offset, token >> 4)
        if offset + literal_length > payload_size:
            raise AppleCompressionError("truncated LZ4 literal run")
        if len(output) + literal_length > uncompressed_size:
            raise AppleCompressionError("LZ4 literal run exceeds expected output size")
        output.extend(payload[offset : offset + literal_length])
        offset += literal_length

        if offset == payload_size:
            break
        if offset + 2 > payload_size:
            raise AppleCompressionError("truncated LZ4 match offset")

        match_offset = payload[offset] | (payload[offset + 1] << 8)
        offset += 2
        if match_offset == 0 or match_offset > len(output):
            raise AppleCompressionError("invalid LZ4 match offset")

        match_length, offset = _read_lz4_length(payload, offset, token & 0x0F)
        match_length += 4
        if len(output) + match_length > uncompressed_size:
            raise AppleCompressionError("LZ4 match exceeds expected output size")
        _extend_lz4_match(output, match_offset, match_length)

    if len(output) != uncompressed_size:
        raise AppleCompressionError("LZ4 output size mismatch")
    return bytes(output)


def _read_lz4_length(payload: bytes, offset: int, value: int) -> tuple[int, int]:
    if value != 15:
        return value, offset

    payload_size = len(payload)
    while True:
        if offset >= payload_size:
            raise AppleCompressionError("truncated LZ4 extended length")
        current = payload[offset]
        offset += 1
        value += current
        if current != 255:
            return value, offset


def _decompress_lz4_raw_fast(payload: bytes, uncompressed_size: int) -> Optional[bytes]:
    try:
        import lz4.block  # type: ignore[import-not-found]
    except ImportError:
        return None
    try:
        return lz4.block.decompress(payload, uncompressed_size=uncompressed_size)
    except Exception:
        return None


def _extend_lz4_match(output: bytearray, match_offset: int, match_length: int) -> None:
    match_start = len(output) - match_offset
    remaining = match_length
    while remaining:
        available = len(output) - match_start
        copy_size = min(available, remaining)
        output.extend(output[match_start : match_start + copy_size])
        remaining -= copy_size


def _decode_macos_compression(payload: bytes) -> Optional[bytes]:
    if platform.system() != "Darwin":
        return None
    if len(payload) < APPLE_COMPRESSION_HEADER_SIZE:
        return None

    magic, uncompressed_size, _compressed_size = struct.unpack_from("<4sII", payload)
    if magic == b"bvxn":
        algorithm = COMPRESSION_LZVN
    elif magic == APPLE_COMPRESSION_LZ4_MAGIC:
        algorithm = COMPRESSION_LZ4
    else:
        return None

    library_path = ctypes.util.find_library("compression") or "/usr/lib/libcompression.dylib"
    try:
        library = ctypes.CDLL(library_path)
    except OSError:
        return None

    dst = ctypes.create_string_buffer(uncompressed_size)
    src = ctypes.create_string_buffer(payload, len(payload))
    decode = library.compression_decode_buffer
    decode.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    decode.restype = ctypes.c_size_t
    decoded_size = decode(dst, uncompressed_size, src, len(payload), None, algorithm)
    if decoded_size == 0:
        return None
    return dst.raw[:decoded_size]
