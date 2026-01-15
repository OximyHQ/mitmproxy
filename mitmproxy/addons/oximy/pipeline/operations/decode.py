"""
Decode operation for the pipeline.

Handles decoding of encoded data:
- base64, base64url: Base64 decoding
- gzip, deflate, br, zstd: Compression decoding
- hex: Hexadecimal decoding
"""

from __future__ import annotations

import base64
import gzip
import logging
import zlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def decode_op(context: PipelineContext, config: dict) -> PipelineContext:
    """
    Decode encoded data in request or response body.

    Config options:
        encoding: str - Type of encoding (base64, base64url, gzip, deflate, br, zstd, hex)
        apply_to: str - "request", "response", or "both" (default: "response")

    Args:
        context: Pipeline context with raw bytes
        config: Operation configuration

    Returns:
        Updated context with decoded data
    """
    encoding = config.get("encoding")
    if not encoding:
        context.set_error("decode: missing 'encoding' field")
        return context

    apply_to = config.get("apply_to", "response")

    if apply_to in ("request", "both"):
        if context.request_body:
            decoded = _decode_bytes(context.request_body, encoding)
            if decoded is not None:
                context.request_body = decoded
            else:
                logger.debug(f"Failed to decode request body with {encoding}")

    if apply_to in ("response", "both"):
        if context.response_body:
            decoded = _decode_bytes(context.response_body, encoding)
            if decoded is not None:
                context.response_body = decoded
            else:
                logger.debug(f"Failed to decode response body with {encoding}")

    return context


def _decode_bytes(data: bytes, encoding: str) -> bytes | None:
    """
    Decode bytes using the specified encoding.

    Args:
        data: Raw bytes to decode
        encoding: Encoding type

    Returns:
        Decoded bytes or None on failure
    """
    try:
        if encoding == "base64":
            return base64.b64decode(data)

        elif encoding == "base64url":
            # URL-safe base64 with potential padding issues
            # Add padding if needed
            padded = data + b"=" * (4 - len(data) % 4)
            return base64.urlsafe_b64decode(padded)

        elif encoding == "gzip":
            return gzip.decompress(data)

        elif encoding == "deflate":
            # Try raw deflate first, then zlib-wrapped
            try:
                return zlib.decompress(data, -zlib.MAX_WBITS)
            except zlib.error:
                return zlib.decompress(data)

        elif encoding == "br":
            # Brotli requires optional dependency
            try:
                import brotli
                return brotli.decompress(data)
            except ImportError:
                logger.warning("Brotli not installed, cannot decode 'br' encoding")
                return None

        elif encoding == "zstd":
            # Zstandard requires optional dependency
            try:
                import zstandard as zstd
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(data)
            except ImportError:
                logger.warning("zstandard not installed, cannot decode 'zstd' encoding")
                return None

        elif encoding == "hex":
            return bytes.fromhex(data.decode("ascii"))

        else:
            logger.warning(f"Unknown encoding: {encoding}")
            return None

    except Exception as e:
        logger.debug(f"Failed to decode with {encoding}: {e}")
        return None


def decode_base64(data: bytes | str) -> bytes | None:
    """Convenience function to decode base64 data."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return _decode_bytes(data, "base64")


def decode_gzip(data: bytes) -> bytes | None:
    """Convenience function to decode gzip data."""
    return _decode_bytes(data, "gzip")
