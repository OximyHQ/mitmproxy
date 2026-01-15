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
        nested_parse: str - JSONata path to a string field to parse as JSON again
        prefix_strip: str - Prefix to strip before parsing (e.g., "//" for anti-XSSI)

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
        if context.response_body:
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
        data: Already parsed data
        path: Simple dot-notation path to the field (e.g., "data.content")

    Returns:
        Data with nested field parsed
    """
    if not isinstance(data, dict):
        return data

    # Simple path navigation (not full JSONata)
    parts = path.split(".")
    current = data
    parent = None
    last_key = None

    for part in parts:
        if isinstance(current, dict) and part in current:
            parent = current
            last_key = part
            current = current[part]
        elif isinstance(current, list):
            try:
                idx = int(part)
                parent = current
                last_key = idx
                current = current[idx]
            except (ValueError, IndexError):
                return data
        else:
            return data

    # Try to parse the found string as JSON
    if isinstance(current, str) and parent is not None and last_key is not None:
        try:
            parsed = json.loads(current)
            if isinstance(parent, dict) and isinstance(last_key, str):
                parent[last_key] = parsed
            elif isinstance(parent, list) and isinstance(last_key, int):
                parent[last_key] = parsed
        except json.JSONDecodeError:
            pass

    return data


def parse_json(data: bytes | str) -> Any:
    """Convenience function to parse JSON."""
    return _parse_data(data, "json")


def decode_jwt(token: str) -> dict | None:
    """Convenience function to decode a JWT."""
    return _decode_jwt(token)
