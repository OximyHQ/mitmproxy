"""
Accumulate operation for the pipeline.

Accumulates data from streaming chunks based on conditional rules.

This operation:
1. Iterates through stream_chunks
2. Evaluates 'rules' conditions on each chunk
3. Extracts fields that match conditions
4. Accumulates fields using specified methods (concat, first, last, append, sum, merge)
"""

from __future__ import annotations

import logging
from typing import Any
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def accumulate_op(context: PipelineContext, config: dict) -> PipelineContext:
    """
    Accumulate data from stream chunks.

    Config options:
        rules: list[dict] - Conditional extraction rules
            Each rule has:
                when: str - JSONata condition
                set: dict - Fields to extract (field -> JSONata expression)
        fields: dict - How to accumulate each field
            field_name -> {from: str, method: str}
            Methods: concat, first, last, append, sum, merge

    Args:
        context: Pipeline context with stream_chunks
        config: Operation configuration

    Returns:
        Updated context with accumulated data
    """
    rules = config.get("rules", [])
    fields_config = config.get("fields", {})

    if not context.stream_chunks:
        return context

    # Initialize accumulator state
    accumulator: dict[str, Any] = {}
    field_values: dict[str, list[Any]] = {}  # Stores all values for each field

    # Process each chunk
    for chunk in context.stream_chunks:
        # Evaluate each rule
        for rule in rules:
            when_condition = rule.get("when")
            set_fields = rule.get("set", {})

            # Check condition
            if when_condition:
                if not _evaluate_condition(when_condition, chunk):
                    continue

            # Extract fields from this chunk
            for field_name, expr in set_fields.items():
                value = _extract_value(expr, chunk)
                if value is not None:
                    if field_name not in field_values:
                        field_values[field_name] = []
                    field_values[field_name].append(value)

    # Apply accumulation methods
    for field_name, values in field_values.items():
        if not values:
            continue

        # Get accumulation config for this field
        field_config = fields_config.get(field_name, {})
        method = field_config.get("method", "last")

        # Apply method
        accumulated_value = _apply_method(values, method)
        if accumulated_value is not None:
            accumulator[field_name] = accumulated_value

    context.accumulated = accumulator
    return context


def _evaluate_condition(condition: str, data: dict) -> bool:
    """
    Evaluate a JSONata-like condition against data.

    Supports:
    - $exists(field) - Check if field exists
    - $type(field) - Get type of field ('string', 'number', 'boolean', 'array', 'object', 'null')
    - $not(expr) - Negate a boolean expression
    - field = 'value' - Simple equality
    - true/false - Literal boolean
    - expr and expr - Logical AND
    - expr or expr - Logical OR
    """
    condition = condition.strip()

    # Handle literal booleans first (simple cases)
    if condition == "true":
        return True
    if condition == "false":
        return False

    # Handle 'and' conditions - check at top level (outside of parentheses)
    # This must be checked before function calls to handle compound conditions
    if _has_top_level_operator(condition, " and "):
        parts = _split_logical(condition, " and ")
        return all(_evaluate_condition(p.strip(), data) for p in parts)

    # Handle 'or' conditions at top level
    if _has_top_level_operator(condition, " or "):
        parts = _split_logical(condition, " or ")
        return any(_evaluate_condition(p.strip(), data) for p in parts)

    # Handle $exists() - must check if the ENTIRE expression is a $exists call
    if condition.startswith("$exists("):
        inner = _extract_function_arg(condition, "$exists(")
        if inner is not None:
            return _path_exists(inner, data)

    # Handle $not()
    if condition.startswith("$not("):
        inner = _extract_function_arg(condition, "$not(")
        if inner is not None:
            return not _evaluate_condition(inner, data)

    # Handle simple equality: field = 'value' or $type(field) = 'string'
    # Check for top-level '=' (not inside parentheses)
    if _has_top_level_operator(condition, " = "):
        eq_pos = _find_top_level_operator(condition, " = ")
        if eq_pos >= 0:
            left = condition[:eq_pos].strip()
            right = condition[eq_pos + 3:].strip()

            # Evaluate left side (could be path or function like $type())
            actual = _evaluate_value(left, data)

            # Evaluate right side (could be literal or path)
            expected = _evaluate_value(right, data)

            return actual == expected

    # Handle simple path check (truthy)
    value = _get_path_value(condition, data)
    return bool(value)


def _has_top_level_operator(condition: str, operator: str) -> bool:
    """Check if an operator exists at the top level (not inside parentheses)."""
    depth = 0
    for i, char in enumerate(condition):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and condition[i:].startswith(operator):
            return True
    return False


def _find_top_level_operator(condition: str, operator: str) -> int:
    """Find the position of an operator at the top level (not inside parentheses)."""
    depth = 0
    for i, char in enumerate(condition):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and condition[i:].startswith(operator):
            return i
    return -1


def _extract_function_arg(condition: str, prefix: str) -> str | None:
    """
    Extract the argument from a function call if the entire condition is that function call.

    For example:
    - _extract_function_arg("$exists(v)", "$exists(") -> "v"
    - _extract_function_arg("$exists(v) and $not(x)", "$exists(") -> None (not entire expr)
    """
    if not condition.startswith(prefix):
        return None

    # Find the matching closing parenthesis
    depth = 1
    start = len(prefix)
    for i in range(start, len(condition)):
        if condition[i] == "(":
            depth += 1
        elif condition[i] == ")":
            depth -= 1
            if depth == 0:
                # Check if this is the end of the condition
                remaining = condition[i + 1:].strip()
                if not remaining:
                    # The entire condition is this function call
                    return condition[start:i].strip()
                else:
                    # There's more after the function call, so it's not the entire expr
                    return None
    return None


def _evaluate_value(expr: str, data: dict) -> Any:
    """
    Evaluate an expression to get its value.

    Handles:
    - $type(path) - Returns type string
    - 'literal' or "literal" - String literals
    - true/false - Boolean literals
    - path - Path to value in data
    """
    expr = expr.strip()

    # Handle $type()
    if expr.startswith("$type(") and expr.endswith(")"):
        path = expr[6:-1].strip()
        value = _get_path_value(path, data)
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int) or isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        return "unknown"

    # Handle string literals
    if (expr.startswith("'") and expr.endswith("'")) or (
        expr.startswith('"') and expr.endswith('"')
    ):
        return expr[1:-1]

    # Handle boolean literals
    if expr == "true":
        return True
    if expr == "false":
        return False

    # Handle numeric literals
    if expr.isdigit():
        return int(expr)
    try:
        return float(expr)
    except ValueError:
        pass

    # Otherwise it's a path
    return _get_path_value(expr, data)


def _split_logical(condition: str, operator: str) -> list[str]:
    """
    Split a condition by a logical operator, respecting parentheses.

    This handles cases like:
    $exists(v) and $type(v) = 'string'

    Where naive split would break function calls.
    """
    parts = []
    current = ""
    depth = 0

    i = 0
    while i < len(condition):
        # Track parenthesis depth
        if condition[i] == "(":
            depth += 1
            current += condition[i]
        elif condition[i] == ")":
            depth -= 1
            current += condition[i]
        elif depth == 0 and condition[i:].startswith(operator):
            # Found operator at top level
            if current.strip():
                parts.append(current.strip())
            current = ""
            i += len(operator) - 1  # Skip the operator (minus 1 for the loop increment)
        else:
            current += condition[i]
        i += 1

    if current.strip():
        parts.append(current.strip())

    return parts


def _path_exists(path: str, data: dict) -> bool:
    """Check if a path exists in the data."""
    value = _get_path_value(path, data)
    return value is not None


def _get_path_value(path: str, data: Any) -> Any:
    """
    Get value at path in data.

    Supports:
    - Simple dot notation: field.subfield
    - Array access: field[0]
    - Wildcard: field[*].subfield
    """
    if not data:
        return None

    parts = _split_path(path)
    current = data

    for part in parts:
        if current is None:
            return None

        if part == "*":
            # Wildcard - applies to arrays
            if isinstance(current, list):
                continue  # Will be handled by next iteration
            return None

        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            # Try index or apply to all items
            if part.isdigit():
                idx = int(part)
                if idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                # Apply path to all items in array
                results = []
                for item in current:
                    if isinstance(item, dict):
                        val = item.get(part)
                        if val is not None:
                            results.append(val)
                current = results if results else None
        else:
            return None

    return current


def _split_path(path: str) -> list[str]:
    """Split a path into parts, handling brackets."""
    parts = []
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
            bracket_content = path[i + 1 : j]
            parts.append(bracket_content)
            i = j
        else:
            current += char

        i += 1

    if current:
        parts.append(current)

    return parts


def _extract_value(expr: str, data: dict) -> Any:
    """
    Extract a value from data using a JSONata-like expression.

    For now, supports:
    - Simple path: field.subfield
    - $join(): Join array values
    - Literal strings in quotes
    """
    expr = expr.strip()

    # Handle $join()
    if expr.startswith("$join("):
        # Extract path and separator
        # $join(field[*].value, '')
        inner = expr[6:-1]
        parts = inner.rsplit(",", 1)
        if len(parts) == 2:
            path = parts[0].strip()
            sep = parts[1].strip().strip("'\"")
            values = _get_path_value(path, data)
            if isinstance(values, list):
                return sep.join(str(v) for v in values if v is not None)
            elif values is not None:
                return str(values)
        return None

    # Handle literal strings
    if expr.startswith("'") and expr.endswith("'"):
        return expr[1:-1]
    if expr.startswith('"') and expr.endswith('"'):
        return expr[1:-1]

    # Simple path extraction
    return _get_path_value(expr, data)


def _apply_method(values: list[Any], method: str) -> Any:
    """Apply accumulation method to a list of values."""
    if not values:
        return None

    if method == "concat":
        # Concatenate strings
        return "".join(str(v) for v in values if v is not None)

    elif method == "first":
        return values[0]

    elif method == "last":
        return values[-1]

    elif method == "append":
        # Return as list
        return values

    elif method == "sum":
        # Sum numeric values
        total = 0
        for v in values:
            if isinstance(v, (int, float)):
                total += v
        return total

    elif method == "merge":
        # Merge dictionaries
        result = {}
        for v in values:
            if isinstance(v, dict):
                result.update(v)
        return result

    else:
        logger.warning(f"Unknown accumulation method: {method}")
        return values[-1]
