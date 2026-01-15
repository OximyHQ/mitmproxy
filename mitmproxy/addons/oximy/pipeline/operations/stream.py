"""
Stream operation for the pipeline.

Handles streaming response formats:
- sse: Server-Sent Events (text/event-stream)
- ndjson: Newline-delimited JSON
- websocket: WebSocket messages
- chunked: Generic chunked responses
- grpc-stream: gRPC streaming
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def stream_op(context: PipelineContext, config: dict) -> PipelineContext:
    """
    Parse streaming response into individual chunks.

    Config options:
        transport: str - Transport type (sse, ndjson, websocket, chunked, grpc-stream)
        apply_to: str - "request" or "response" (default: "response")
        options: dict - Transport-specific options:
            prefixes: list[str] - Prefixes to strip from each line (e.g., ["data: "])
            skip: list[str] - Lines/values to skip (e.g., ["[DONE]"])
            delimiter: str - Chunk delimiter (default: newline)
            end_signal: str - Signal that indicates end of stream
            prefix_strip: str - One-time prefix to strip from start
            chunk_format: str - "line" (default) or "length_prefixed"

    Args:
        context: Pipeline context with raw bytes
        config: Operation configuration

    Returns:
        Updated context with stream_chunks populated
    """
    transport = config.get("transport")
    if not transport:
        context.set_error("stream: missing 'transport' field")
        return context

    apply_to = config.get("apply_to", "response")
    options = config.get("options", {})

    # Get the body to parse
    if apply_to == "request":
        body = context.request_body
    else:
        body = context.response_body

    if not body:
        return context

    # Decode body to text
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.decode("latin-1")

    # Strip one-time prefix if specified
    prefix_strip = options.get("prefix_strip")
    if prefix_strip and text.startswith(prefix_strip):
        text = text[len(prefix_strip):]

    # Parse based on transport type
    if transport == "sse":
        chunks = _parse_sse(text, options)
    elif transport == "ndjson":
        chunks = _parse_ndjson(text, options)
    elif transport == "chunked":
        chunk_format = options.get("chunk_format", "line")
        if chunk_format == "length_prefixed":
            chunks = _parse_length_prefixed(text, options)
        else:
            chunks = _parse_line_delimited(text, options)
    elif transport == "websocket":
        # WebSocket messages need special handling
        chunks = _parse_websocket(text, options)
    elif transport == "grpc-stream":
        # gRPC streaming not yet implemented
        logger.debug("gRPC stream parsing not yet implemented")
        chunks = []
    else:
        logger.warning(f"Unknown stream transport: {transport}")
        chunks = []

    context.stream_chunks = chunks

    # Also set response_data to the list of chunks for extraction
    if apply_to == "response":
        context.response_data = chunks
    else:
        context.request_data = chunks

    return context


def _parse_sse(text: str, options: dict) -> list[dict]:
    """
    Parse Server-Sent Events format.

    SSE format:
        event: message
        data: {"content": "hello"}

        data: {"content": "world"}

    """
    chunks = []
    prefixes = options.get("prefixes", ["data: "])
    skip = options.get("skip", ["[DONE]"])

    current_event = None
    current_data_lines = []

    for line in text.split("\n"):
        line = line.rstrip("\r")

        if not line:
            # Empty line marks end of event
            if current_data_lines:
                data_str = "\n".join(current_data_lines)
                if data_str not in skip:
                    chunk = _try_parse_json(data_str)
                    if chunk is not None:
                        if current_event:
                            chunk["_event"] = current_event
                        chunks.append(chunk)
                current_data_lines = []
                current_event = None
            continue

        if line.startswith("event:"):
            current_event = line[6:].strip()
            continue

        if line.startswith("id:") or line.startswith("retry:"):
            continue

        # Check for data prefixes
        for prefix in prefixes:
            if line.startswith(prefix):
                data_line = line[len(prefix):]
                if data_line not in skip:
                    current_data_lines.append(data_line)
                break
        else:
            # No prefix matched, could be a continuation
            if line.startswith("data:"):
                data_line = line[5:].strip()
                if data_line not in skip:
                    current_data_lines.append(data_line)

    # Handle any remaining data
    if current_data_lines:
        data_str = "\n".join(current_data_lines)
        if data_str not in skip:
            chunk = _try_parse_json(data_str)
            if chunk is not None:
                if current_event:
                    chunk["_event"] = current_event
                chunks.append(chunk)

    return chunks


def _parse_ndjson(text: str, options: dict) -> list[dict]:
    """Parse newline-delimited JSON."""
    chunks = []
    skip = options.get("skip", [])
    prefixes = options.get("prefixes", [])

    for line in text.split("\n"):
        line = line.strip()
        if not line or line in skip:
            continue

        # Strip prefixes if specified
        for prefix in prefixes:
            if line.startswith(prefix):
                line = line[len(prefix):]
                break

        if line in skip:
            continue

        chunk = _try_parse_json(line)
        if chunk is not None:
            chunks.append(chunk)

    return chunks


def _parse_line_delimited(text: str, options: dict) -> list[dict]:
    """Parse generic line-delimited format."""
    chunks = []
    delimiter = options.get("delimiter", "\n")
    skip = options.get("skip", [])
    prefixes = options.get("prefixes", [])

    lines = text.split(delimiter) if delimiter == "\n" else text.split(delimiter)

    for line in lines:
        line = line.strip()
        if not line or line in skip:
            continue

        # Strip prefixes if specified
        for prefix in prefixes:
            if line.startswith(prefix):
                line = line[len(prefix):]
                break

        if line in skip:
            continue

        chunk = _try_parse_json(line)
        if chunk is not None:
            chunks.append(chunk)

    return chunks


def _parse_length_prefixed(text: str, options: dict) -> list[dict]:
    """
    Parse length-prefixed chunks.

    Format: <length>\n<json>\n<length>\n<json>...

    Used by Google's streaming API.
    """
    chunks = []
    skip = options.get("skip", [])
    lines = text.split("\n")

    i = 0
    while i < len(lines):
        # Skip empty lines
        if not lines[i].strip():
            i += 1
            continue

        # Try to read length
        try:
            length = int(lines[i].strip())
            i += 1

            # Collect data until we have enough bytes
            data = ""
            while i < len(lines) and len(data) < length:
                data += lines[i]
                if len(data) < length:
                    data += "\n"
                i += 1

            if data and data not in skip:
                chunk = _try_parse_json(data)
                if chunk is not None:
                    chunks.append(chunk)

        except ValueError:
            # Not a length line, try parsing as JSON
            if lines[i].strip() and lines[i].strip() not in skip:
                chunk = _try_parse_json(lines[i].strip())
                if chunk is not None:
                    chunks.append(chunk)
            i += 1

    return chunks


def _parse_websocket(text: str, options: dict) -> list[dict]:
    """Parse WebSocket messages (simplified)."""
    # WebSocket parsing is complex and depends on how messages are captured
    # For now, try to parse as newline-delimited JSON
    return _parse_ndjson(text, options)


def _try_parse_json(text: str) -> dict | None:
    """Try to parse text as JSON, return None on failure."""
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
        elif isinstance(result, list):
            return {"_items": result}
        else:
            return {"_value": result}
    except json.JSONDecodeError:
        return None
