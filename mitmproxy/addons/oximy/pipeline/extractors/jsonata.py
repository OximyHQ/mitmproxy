"""
JSONata expression evaluation for field extraction.

Provides a simplified JSONata-like evaluator that handles:
- Simple path expressions: field.subfield
- Array access: field[0], field[*]
- Special variables: $request, $response, $accumulated, $headers
- Built-in functions: $exists(), $join(), $type()
- Conditional expressions

For complex expressions, falls back to the jsonata-python library if available.
"""

from __future__ import annotations

import logging
import re
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)

# Try to import jsonata-python for full JSONata support
try:
    import jsonata as jsonata_lib

    JSONATA_AVAILABLE = True
except ImportError:
    jsonata_lib = None  # type: ignore
    JSONATA_AVAILABLE = False
    logger.debug("jsonata-python not installed, using simplified evaluator")


def extract_fields(
    context: PipelineContext,
    extract_config: dict[str, str],
) -> dict[str, Any]:
    """
    Extract fields from context using JSONata expressions.

    Args:
        context: Pipeline context with parsed data
        extract_config: Map of field_name -> JSONata expression

    Returns:
        Dict of extracted field_name -> value
    """
    extracted: dict[str, Any] = {}

    # Build evaluation context
    eval_context = {
        "request": context.request_data,
        "response": context.response_data,
        "accumulated": context.accumulated,
        "headers": {
            "request": context.request_headers,
            "response": context.response_headers,
        },
    }

    for field_name, expr in extract_config.items():
        try:
            value = evaluate_expression(expr, eval_context)
            if value is not None:
                extracted[field_name] = value
        except Exception as e:
            logger.debug(f"Failed to extract {field_name} with '{expr}': {e}")

    return extracted


def evaluate_expression(expr: str, context: dict) -> Any:
    """
    Evaluate a JSONata expression against context.

    Supports special variable prefixes:
    - $request. -> context["request"]
    - $response. -> context["response"]
    - $accumulated. -> context["accumulated"]
    - $headers. -> context["headers"]

    Args:
        expr: JSONata expression
        context: Evaluation context dict

    Returns:
        Evaluated value or None
    """
    expr = expr.strip()

    # Handle special variable prefixes
    if expr.startswith("$request."):
        return _evaluate_path(expr[9:], context.get("request"))
    if expr.startswith("$response."):
        return _evaluate_path(expr[10:], context.get("response"))
    if expr.startswith("$accumulated."):
        return _evaluate_path(expr[13:], context.get("accumulated"))
    if expr.startswith("$headers."):
        return _evaluate_path(expr[9:], context.get("headers"))

    # Handle literal strings
    if (expr.startswith("'") and expr.endswith("'")) or (
        expr.startswith('"') and expr.endswith('"')
    ):
        return expr[1:-1]

    # Handle built-in functions
    if expr.startswith("$"):
        return _evaluate_function(expr, context)

    # Try jsonata-python for complex expressions
    if JSONATA_AVAILABLE and _is_complex_expression(expr):
        return _evaluate_jsonata(expr, context)

    # Simple path evaluation against merged context
    merged = _merge_context(context)
    return _evaluate_path(expr, merged)


def _evaluate_path(path: str, data: Any) -> Any:
    """
    Evaluate a simple dot-notation path.

    Supports:
    - field.subfield
    - field[0]
    - field[*].subfield
    - field[key='value']
    """
    if data is None or not path:
        return None

    parts = _split_path(path)
    current = data

    for part in parts:
        if current is None:
            return None

        # Handle array wildcard
        if part == "*":
            if isinstance(current, list):
                continue  # Next part will apply to all items
            return None

        # Handle filter expression: [key='value']
        filter_match = re.match(r"\[([^=]+)='([^']+)'\]", part)
        if filter_match:
            key, value = filter_match.groups()
            if isinstance(current, list):
                for item in current:
                    if isinstance(item, dict) and item.get(key) == value:
                        current = item
                        break
                else:
                    current = None
            continue

        # Handle array index
        if isinstance(current, list):
            if part.isdigit():
                idx = int(part)
                if idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                # Apply path to all items and collect results
                results = []
                for item in current:
                    if isinstance(item, dict):
                        val = item.get(part)
                        if val is not None:
                            results.append(val)
                current = results if results else None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None

    return current


def _split_path(path: str) -> list[str]:
    """Split a path into parts, handling brackets and filters."""
    parts = []
    current = ""
    bracket_depth = 0

    for char in path:
        if char == "." and bracket_depth == 0:
            if current:
                parts.append(current)
                current = ""
        elif char == "[":
            if current and bracket_depth == 0:
                parts.append(current)
                current = ""
            current += char
            bracket_depth += 1
        elif char == "]":
            current += char
            bracket_depth -= 1
            if bracket_depth == 0:
                parts.append(current)
                current = ""
        else:
            current += char

    if current:
        parts.append(current)

    # Clean up bracket parts
    cleaned = []
    for part in parts:
        if part.startswith("[") and part.endswith("]"):
            inner = part[1:-1]
            # Check if it's an index or filter
            if inner.isdigit() or inner == "*" or "=" in inner:
                cleaned.append(inner if inner.isdigit() or inner == "*" else part)
            else:
                cleaned.append(inner)
        else:
            cleaned.append(part)

    return cleaned


def _evaluate_function(expr: str, context: dict) -> Any:
    """Evaluate built-in functions."""
    # $exists(path)
    if expr.startswith("$exists(") and expr.endswith(")"):
        path = expr[8:-1].strip()
        value = evaluate_expression(path, context)
        return value is not None

    # $join(array, separator)
    if expr.startswith("$join(") and expr.endswith(")"):
        inner = expr[6:-1]
        # Find separator (last comma-separated part)
        parts = inner.rsplit(",", 1)
        if len(parts) == 2:
            array_expr = parts[0].strip()
            sep = parts[1].strip().strip("'\"")
            values = evaluate_expression(array_expr, context)
            if isinstance(values, list):
                return sep.join(str(v) for v in values if v is not None)
        return None

    # $type(expr)
    if expr.startswith("$type(") and expr.endswith(")"):
        inner_expr = expr[6:-1].strip()
        value = evaluate_expression(inner_expr, context)
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "number"
        if isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        return "unknown"

    # $parseJson(expr) - parse a JSON string
    if expr.startswith("$parseJson(") and expr.endswith(")"):
        inner_expr = expr[11:-1].strip()
        value = evaluate_expression(inner_expr, context)
        if isinstance(value, str):
            import json
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return None
        return value

    # Unknown function
    logger.debug(f"Unknown function: {expr}")
    return None


def _is_complex_expression(expr: str) -> bool:
    """Check if expression requires full JSONata evaluation."""
    complex_patterns = [
        "?",  # Conditional
        "(",  # Grouping (not function)
        "[?",  # Filter
        "*.",  # Descendant
        "**",  # Recursive descent
        "&",  # Concatenation
        "+",  # Arithmetic
        "-",  # Arithmetic
        "*",  # Multiplication (not wildcard)
        "/",  # Division
        "%",  # Modulo
    ]
    return any(p in expr for p in complex_patterns)


def _evaluate_jsonata(expr: str, context: dict) -> Any:
    """Evaluate using jsonata-python library."""
    if jsonata_lib is None:
        return None
    try:
        # Merge context into single dict for evaluation
        merged = _merge_context(context)
        result = jsonata_lib.Jsonata(expr).evaluate(merged)
        return result
    except Exception as e:
        logger.debug(f"JSONata evaluation failed for '{expr}': {e}")
        return None


def _merge_context(context: dict) -> dict:
    """Merge context parts into a single dict for evaluation."""
    merged: dict[str, Any] = {}

    # Add request and response at top level
    if context.get("request"):
        if isinstance(context["request"], dict):
            merged.update(context["request"])

    if context.get("response"):
        if isinstance(context["response"], dict):
            merged.update(context["response"])

    # Add special keys
    if context.get("accumulated"):
        merged["_accumulated"] = context["accumulated"]

    if context.get("headers"):
        merged["_headers"] = context["headers"]

    return merged
