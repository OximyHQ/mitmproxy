"""
Branch operation for the pipeline.

Conditional branching based on data content.
Allows different extraction paths based on data structure.
"""

from __future__ import annotations

import logging
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def branch_op(context: PipelineContext, config: dict) -> PipelineContext:
    """
    Apply conditional branching based on data content.

    Config options:
        on: str - JSONata expression to evaluate for branching
        cases: dict - Map of case values to extraction configs
            Each case value maps to a dict of field -> JSONata expression

    Example:
        {
            "op": "branch",
            "on": "type",
            "cases": {
                "message": {"content": "text"},
                "tool_use": {"tool_name": "name", "tool_input": "input"}
            }
        }

    Args:
        context: Pipeline context
        config: Operation configuration

    Returns:
        Updated context with extracted fields
    """
    on_expr = config.get("on")
    cases = config.get("cases", {})

    if not on_expr or not cases:
        return context

    # Get data to branch on
    data = context.response_data
    if not data:
        data = context.request_data
    if not data:
        return context

    # Handle array of items - apply to each
    if isinstance(data, list):
        results = []
        for item in data:
            result = _apply_branch(item, on_expr, cases)
            if result:
                results.append(result)
        if results:
            context.extracted.update({"_branched": results})
        return context

    # Single item
    result = _apply_branch(data, on_expr, cases)
    if result:
        context.extracted.update(result)

    return context


def _apply_branch(data: Any, on_expr: str, cases: dict) -> dict | None:
    """Apply branching to a single data item."""
    if not isinstance(data, dict):
        return None

    # Evaluate the "on" expression to get case value
    case_value = _get_value(data, on_expr)
    if case_value is None:
        return None

    # Convert to string for case matching
    case_key = str(case_value)

    # Find matching case
    extractions = cases.get(case_key)
    if not extractions:
        # Try default case
        extractions = cases.get("_default") or cases.get("default")
        if not extractions:
            return None

    # Apply extractions
    result: dict = {"_case": case_key}
    for field_name, expr in extractions.items():
        value = _get_value(data, expr)
        if value is not None:
            result[field_name] = value

    return result


def _get_value(data: dict, path: str) -> Any:
    """
    Get value at path in data.

    Supports simple dot notation: field.subfield
    """
    if not path:
        return None

    # Handle literal strings
    if path.startswith("'") and path.endswith("'"):
        return path[1:-1]
    if path.startswith('"') and path.endswith('"'):
        return path[1:-1]

    parts = path.split(".")
    current = data

    for part in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None

    return current
