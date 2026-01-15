"""
Extract authentication operation for the pipeline.

Handles extraction of authentication information:
- JWT token decoding
- Bearer token extraction
- API key extraction from headers
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def extract_auth_op(context: PipelineContext, config: dict) -> PipelineContext:
    """
    Extract authentication information.

    Config options:
        format: str - "jwt" (decode JWT), "bearer" (extract bearer token)
        field: str - Field name containing the token (in parsed data)
        header: str - Header name to extract from (alternative to field)

    Args:
        context: Pipeline context
        config: Operation configuration

    Returns:
        Updated context with extracted auth info
    """
    fmt = config.get("format", "jwt")
    field = config.get("field")
    header = config.get("header")

    token = None

    # Get token from field in parsed data
    if field:
        # Check response data first, then request
        if context.response_data and isinstance(context.response_data, dict):
            token = _get_nested_value(context.response_data, field)
        if not token and context.request_data and isinstance(context.request_data, dict):
            token = _get_nested_value(context.request_data, field)

    # Or get token from header
    if not token and header:
        header_lower = header.lower()
        token = context.response_headers.get(header_lower) or context.request_headers.get(header_lower)

    if not token:
        return context

    # Process based on format
    if fmt == "jwt":
        decoded = _decode_jwt(token)
        if decoded:
            # Merge decoded JWT into response_data
            if context.response_data is None:
                context.response_data = {}
            if isinstance(context.response_data, dict):
                context.response_data["_jwt"] = decoded
                # Also flatten common fields
                for key in ["sub", "email", "name", "exp", "iat"]:
                    if key in decoded:
                        context.response_data[f"_jwt_{key}"] = decoded[key]

    elif fmt == "bearer":
        # Just extract the bearer token
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if context.response_data is None:
            context.response_data = {}
        if isinstance(context.response_data, dict):
            context.response_data["_bearer_token"] = token

    return context


def _get_nested_value(data: dict, path: str) -> Any:
    """Get a nested value from a dict using dot notation."""
    parts = path.split(".")
    current = data

    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None

    return current


def _decode_jwt(token: str) -> dict | None:
    """
    Decode a JWT token without verification.

    Returns the payload as a dict.
    """
    try:
        # JWT format: header.payload.signature
        # Handle tokens that might have "Bearer " prefix
        if token.lower().startswith("bearer "):
            token = token[7:].strip()

        parts = token.strip().split(".")
        if len(parts) != 3:
            return None

        # Decode payload (second part)
        payload = parts[1]
        # Add padding if needed (base64url requires padding)
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)

    except Exception as e:
        logger.debug(f"Failed to decode JWT: {e}")
        return None


def decode_jwt(token: str) -> dict | None:
    """Public function to decode a JWT."""
    return _decode_jwt(token)
