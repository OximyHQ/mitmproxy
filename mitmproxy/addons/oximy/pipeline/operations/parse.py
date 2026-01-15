"""
Parse operation for the pipeline.

Handles parsing of various data formats:
- json: JSON parsing
- xml: XML parsing
- form: URL-encoded form data
- multipart: Multipart form data
- graphql: GraphQL request parsing
- yaml: YAML parsing
- msgpack: MessagePack parsing
- jwt: JWT token decoding (without signature verification)
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any
from typing import TYPE_CHECKING
from urllib.parse import parse_qs

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def parse_op(context: PipelineContext, config: dict) -> PipelineContext:
    """
    Parse raw bytes into structured data.

    Config options:
        format: str - Format to parse (json, xml, form, graphql, yaml, msgpack, jwt)
        apply_to: str - "request", "response", or "both" (default: "both")
        nested_parse: str - Path to a string field to parse as JSON (e.g., "[0][2]")
        prefix_strip: str - Prefix to strip before parsing (e.g., "//" for anti-XSSI)

    If response_data/stream_chunks already exist (e.g., from stream op) and nested_parse
    is specified, the nested_parse will be applied to each chunk instead of re-parsing.

    Args:
        context: Pipeline context with raw bytes
        config: Operation configuration

    Returns:
        Updated context with parsed data
    """
    fmt = config.get("format")
    if not fmt:
        context.set_error("parse: missing 'format' field")
        return context

    apply_to = config.get("apply_to", "both")
    prefix_strip = config.get("prefix_strip")
    nested_parse = config.get("nested_parse")

    if apply_to in ("request", "both"):
        if context.request_body:
            data = context.request_body
            if prefix_strip and isinstance(data, bytes):
                data = _strip_prefix(data, prefix_strip)
            parsed = _parse_data(data, fmt)
            if parsed is not None:
                if nested_parse:
                    parsed = _apply_nested_parse(parsed, nested_parse)
                context.request_data = parsed

    if apply_to in ("response", "both"):
        # If stream_chunks exist and we have nested_parse, apply to each chunk
        if context.stream_chunks and nested_parse:
            parsed_chunks = []
            for chunk in context.stream_chunks:
                parsed_chunk = _apply_nested_parse(chunk, nested_parse)
                parsed_chunks.append(parsed_chunk)
            context.stream_chunks = parsed_chunks
            context.response_data = parsed_chunks
        elif context.response_body:
            data = context.response_body
            if prefix_strip and isinstance(data, bytes):
                data = _strip_prefix(data, prefix_strip)
            parsed = _parse_data(data, fmt)
            if parsed is not None:
                if nested_parse:
                    parsed = _apply_nested_parse(parsed, nested_parse)
                context.response_data = parsed

    return context


def _strip_prefix(data: bytes, prefix: str) -> bytes:
    """Strip a prefix from data if present."""
    prefix_bytes = prefix.encode("utf-8")
    if data.startswith(prefix_bytes):
        return data[len(prefix_bytes):]
    return data


def _parse_data(data: bytes | str, fmt: str) -> Any:
    """
    Parse data according to format.

    Args:
        data: Raw data to parse
        fmt: Format type

    Returns:
        Parsed data or None on failure
    """
    if isinstance(data, bytes):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1")
    else:
        text = data

    try:
        if fmt == "json":
            return json.loads(text)

        elif fmt == "form":
            # URL-encoded form data
            parsed = parse_qs(text, keep_blank_values=True)
            # Convert single-value lists to single values
            return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}

        elif fmt == "graphql":
            # GraphQL requests are JSON with specific structure
            parsed = json.loads(text)
            return parsed

        elif fmt == "xml":
            # XML requires optional dependency
            try:
                import xmltodict
                return xmltodict.parse(text)
            except ImportError:
                logger.warning("xmltodict not installed, cannot parse XML")
                return None

        elif fmt == "yaml":
            # YAML requires optional dependency
            try:
                import yaml
                return yaml.safe_load(text)
            except ImportError:
                logger.warning("PyYAML not installed, cannot parse YAML")
                return None

        elif fmt == "msgpack":
            # MessagePack requires optional dependency
            try:
                import msgpack
                if isinstance(data, str):
                    data = data.encode("utf-8")
                return msgpack.unpackb(data, raw=False)
            except ImportError:
                logger.warning("msgpack not installed, cannot parse MessagePack")
                return None

        elif fmt == "jwt":
            # Decode JWT without verification
            if isinstance(text, str):
                return _decode_jwt(text)
            return None

        elif fmt == "multipart":
            # Multipart parsing is complex, return as-is for now
            logger.debug("Multipart parsing not yet implemented")
            return None

        elif fmt == "protobuf":
            # Protobuf requires schema, not implemented here
            logger.debug("Protobuf parsing requires schema")
            return None

        else:
            logger.warning(f"Unknown parse format: {fmt}")
            return None

    except Exception as e:
        logger.debug(f"Failed to parse as {fmt}: {e}")
        return None


def _decode_jwt(token: str) -> dict | None:
    """
    Decode a JWT token without verification.

    Returns the payload as a dict.
    """
    try:
        # JWT format: header.payload.signature
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None

        # Decode payload (second part)
        payload = parts[1]
        # Add padding if needed
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    except Exception as e:
        logger.debug(f"Failed to decode JWT: {e}")
        return None


def _apply_nested_parse(data: Any, path: str) -> Any:
    """
    Apply nested JSON parsing to a string field within parsed data.

    This handles cases like Google's batchexecute where the response
    contains a JSON string that needs to be parsed again.

    Args:
        data: Already parsed data (can be dict or list)
        path: Path to the field, supports both bracket notation ([0][2])
              and dot notation (data.content)

    Returns:
        Data with nested field parsed, or extracted nested data
    """
    if data is None:
        return data

    # Handle stream chunks that wrap arrays in {"_items": [...]}
    # This allows paths like [0][2] to work on stream output
    if isinstance(data, dict) and "_items" in data and path.startswith("["):
        data = data["_items"]

    # Parse the path into parts, handling bracket notation
    parts = _parse_path(path)
    if not parts:
        return data

    # Navigate to the target
    current = data
    for part in parts:
        if current is None:
            return data

        if isinstance(part, int):
            # Array index
            if isinstance(current, list) and 0 <= part < len(current):
                current = current[part]
            else:
                return data
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return data

    # If we found a string, parse it as JSON and return the parsed result
    if isinstance(current, str):
        try:
            return json.loads(current)
        except json.JSONDecodeError:
            return current

    return current


def _parse_path(path: str) -> list[str | int]:
    """
    Parse a path string into parts.

    Handles:
    - Bracket notation: [0][2]
    - Dot notation: data.content
    - Mixed: data[0].content

    Returns list of string keys and int indices.
    """
    parts: list[str | int] = []
    current = ""
    i = 0

    while i < len(path):
        char = path[i]

        if char == ".":
            if current:
                parts.append(current)
                current = ""
        elif char == "[":
            if current:
                parts.append(current)
                current = ""
            # Find closing bracket
            j = i + 1
            while j < len(path) and path[j] != "]":
                j += 1
            bracket_content = path[i + 1:j]
            # Check if it's an integer index
            try:
                parts.append(int(bracket_content))
            except ValueError:
                parts.append(bracket_content)
            i = j
        else:
            current += char

        i += 1

    if current:
        parts.append(current)

    return parts


def parse_json(data: bytes | str) -> Any:
    """Convenience function to parse JSON."""
    return _parse_data(data, "json")


def decode_jwt(token: str) -> dict | None:
    """Convenience function to decode a JWT."""
    return _decode_jwt(token)
