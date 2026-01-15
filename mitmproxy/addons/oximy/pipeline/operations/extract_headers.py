"""
Extract headers operation for the pipeline.

Extracts specific headers and adds them to the context.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def extract_headers_op(context: PipelineContext, config: dict) -> PipelineContext:
    """
    Extract specific headers into the context.

    Config options:
        headers: list[str] | dict[str, str] - Headers to extract
            If list: Extract headers with same name
            If dict: Map header name to output field name
        from: str - "request" or "response" (default: "response")

    Args:
        context: Pipeline context with headers
        config: Operation configuration

    Returns:
        Updated context with extracted headers
    """
    headers_config = config.get("headers", [])
    from_source = config.get("from", "response")

    source_headers = (
        context.request_headers if from_source == "request" else context.response_headers
    )

    extracted: dict = {}

    if isinstance(headers_config, list):
        # List of header names
        for header in headers_config:
            header_lower = header.lower()
            if header_lower in source_headers:
                extracted[header] = source_headers[header_lower]

    elif isinstance(headers_config, dict):
        # Dict mapping header -> output field name
        for header, output_name in headers_config.items():
            header_lower = header.lower()
            if header_lower in source_headers:
                extracted[output_name] = source_headers[header_lower]

    # Merge into response_data or request_data
    if from_source == "request":
        if context.request_data is None:
            context.request_data = {}
        if isinstance(context.request_data, dict):
            context.request_data["_headers"] = extracted
    else:
        if context.response_data is None:
            context.response_data = {}
        if isinstance(context.response_data, dict):
            context.response_data["_headers"] = extracted

    return context
