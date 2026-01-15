"""
Normalizer for mapping extracted fields to trace-output schema.

Takes the extracted fields from pipeline processing and maps them
to the normalized output format defined in trace-output.schema.json.
"""

from __future__ import annotations

import logging
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

from mitmproxy.addons.oximy.pipeline.extractors.jsonata import evaluate_expression

logger = logging.getLogger(__name__)


def normalize_output(
    context: PipelineContext,
    normalize_config: dict[str, str],
) -> dict[str, Any]:
    """
    Normalize extracted fields to trace-output schema.

    The normalize_config maps output field paths to JSONata expressions
    that reference extracted fields.

    Example normalize_config:
        {
            "interaction.type": "'chat'",
            "interaction.input.text": "$request.prompt",
            "interaction.output.text": "$response.content",
            "interaction.model": "$response.model"
        }

    Args:
        context: Pipeline context with extracted data
        normalize_config: Map of output path -> JSONata expression

    Returns:
        Normalized dict matching trace-output schema structure
    """
    result: dict[str, Any] = {}

    # Build evaluation context from context
    eval_context = {
        "request": context.request_data,
        "response": context.response_data,
        "accumulated": context.accumulated,
        "extracted": context.extracted,
    }

    # Also add extracted fields at top level for direct reference
    if context.extracted:
        eval_context.update(context.extracted)

    for output_path, expr in normalize_config.items():
        try:
            value = evaluate_expression(expr, eval_context)
            if value is not None:
                _set_nested_value(result, output_path, value)
        except Exception as e:
            logger.debug(f"Failed to normalize {output_path} with '{expr}': {e}")

    return result


def _set_nested_value(data: dict, path: str, value: Any) -> None:
    """
    Set a value at a nested path in a dict.

    Creates intermediate dicts as needed.

    Args:
        data: Target dict
        path: Dot-notation path (e.g., "interaction.input.text")
        value: Value to set
    """
    parts = path.split(".")
    current = data

    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        current = current[part]

    current[parts[-1]] = value


def build_trace_output_dict(
    context: PipelineContext,
    output_config: dict,
    source_info: dict,
) -> dict[str, Any]:
    """
    Build a complete trace output dict from pipeline context.

    Args:
        context: Pipeline context after processing
        output_config: Output config from feature (mode, tag, normalize)
        source_info: Source information (type, tool_id, feature, etc.)

    Returns:
        Dict ready for TraceOutput conversion
    """
    normalize_config = output_config.get("normalize", {})
    include_raw = output_config.get("include_raw", False)

    # Normalize extracted data
    normalized = normalize_output(context, normalize_config)

    # Build result dict
    result: dict[str, Any] = {
        "source": source_info,
    }

    # Add normalized interaction data
    if "interaction" in normalized:
        result["interaction"] = normalized["interaction"]
    else:
        # Create minimal interaction if not normalized
        result["interaction"] = {"type": "other"}

    # Add transport info
    if context.url or context.method or context.status_code:
        result["transport"] = {}
        if context.url:
            result["transport"]["url"] = context.url
            # Determine protocol from URL
            if context.url.startswith("https://"):
                result["transport"]["protocol"] = "https"
            elif context.url.startswith("http://"):
                result["transport"]["protocol"] = "http"
            elif context.url.startswith("wss://"):
                result["transport"]["protocol"] = "wss"
            elif context.url.startswith("ws://"):
                result["transport"]["protocol"] = "ws"
        if context.method:
            result["transport"]["method"] = context.method
        if context.status_code:
            result["transport"]["status_code"] = context.status_code

        # Add content type if available
        content_type = context.get_content_type(from_request=False)
        if content_type:
            result["transport"]["content_type"] = content_type

    # Add raw data if requested
    if include_raw:
        raw = {}
        if context.request_data:
            raw["request"] = context.request_data
        if context.response_data:
            raw["response"] = context.response_data
        if raw:
            result["_raw"] = raw

    # Add any additional normalized fields at top level
    for key in ["usage", "context", "meta", "timing"]:
        if key in normalized:
            result[key] = normalized[key]

    return result
