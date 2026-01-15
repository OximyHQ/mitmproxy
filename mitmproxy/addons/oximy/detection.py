"""
Detection processor for extracting context metadata.

Processes detection sources defined in tool configs to extract:
- Subscription/plan information
- User information
- Organization information
- Rate limit information
- Any other contextual metadata

Detection sources are evaluated opportunistically - they match specific
endpoints and extract metadata when available.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mitmproxy.addons.oximy.pipeline.context import PipelineContext
from mitmproxy.addons.oximy.pipeline.executor import Pipeline
from mitmproxy.addons.oximy.pipeline.extractors.jsonata import evaluate_expression

logger = logging.getLogger(__name__)


class DetectionProcessor:
    """
    Processes detection sources to extract context metadata.

    Detection sources are defined in tool configs and match specific
    endpoints to extract metadata like subscription info, user info, etc.
    """

    def __init__(self):
        # Accumulated context per tool
        self._context_cache: dict[str, dict[str, Any]] = {}

    def process(
        self,
        context: PipelineContext,
        detection_sources: list[dict],
        tool_id: str,
    ) -> dict[str, Any] | None:
        """
        Process detection sources against a request/response.

        Args:
            context: Pipeline context with request/response data
            detection_sources: List of detection source configs from tool config
            tool_id: Tool identifier for caching

        Returns:
            Extracted context dict or None if no matches
        """
        if not detection_sources:
            return None

        extracted: dict[str, Any] = {}

        for source in detection_sources:
            source_id = source.get("id", "unknown")

            # Check URL match
            match_config = source.get("match", {})
            url_pattern = match_config.get("url")

            if url_pattern and context.url:
                if not self._url_matches(context.url, url_pattern):
                    continue

            # Check method match
            method = match_config.get("method")
            if method and context.method and method != "*":
                if context.method.upper() != method.upper():
                    continue

            # Determine extract location
            extract_from = source.get("extract_from", "response_body")

            # Run pipeline if specified
            pipeline_ops = source.get("pipeline", [])
            if pipeline_ops:
                pipeline = Pipeline(pipeline_ops)
                context = pipeline.execute(context)

            # Get data to extract from, auto-parsing JSON if needed
            if extract_from == "response_body":
                data = context.response_data
                if data is None and context.response_body:
                    # Auto-parse JSON from response body
                    data = self._try_parse_json(context.response_body)
            elif extract_from == "request_body":
                data = context.request_data
                if data is None and context.request_body:
                    # Auto-parse JSON from request body
                    data = self._try_parse_json(context.request_body)
            elif extract_from == "response_headers":
                data = context.response_headers
            elif extract_from == "request_headers":
                data = context.request_headers
            else:
                data = context.response_data
                if data is None and context.response_body:
                    data = self._try_parse_json(context.response_body)

            if not data:
                continue

            # Check "when" condition if specified
            when_condition = source.get("when")
            if when_condition:
                eval_context = {"response": data, "request": context.request_data}
                if not self._evaluate_condition(when_condition, eval_context):
                    continue

            # Extract fields
            extract_config = source.get("extract", {})
            if extract_config:
                source_extracted = self._extract_detection_fields(
                    data, extract_config, context
                )
                if source_extracted:
                    # Merge into extracted, organizing by path prefix
                    self._merge_extracted(extracted, source_extracted)
                    logger.debug(
                        f"Detection source '{source_id}' extracted: {list(source_extracted.keys())}"
                    )

        if extracted:
            # Cache for this tool
            if tool_id not in self._context_cache:
                self._context_cache[tool_id] = {}
            self._deep_merge(self._context_cache[tool_id], extracted)
            return extracted

        return None

    def get_context(self, tool_id: str) -> dict[str, Any]:
        """Get all accumulated context for a tool."""
        return self._context_cache.get(tool_id, {}).copy()

    def consume_context(self, tool_id: str) -> dict[str, Any]:
        """
        Get and clear context for a tool atomically.

        This is the primary method for attaching detection context to feature events.
        The context is consumed (cleared) after retrieval so it won't be duplicated.

        Returns:
            Accumulated context dict, or empty dict if none
        """
        context = self._context_cache.pop(tool_id, {})
        return context

    def clear_context(self, tool_id: str | None = None) -> None:
        """Clear cached context for a tool or all tools."""
        if tool_id:
            self._context_cache.pop(tool_id, None)
        else:
            self._context_cache.clear()

    def _try_parse_json(self, body: bytes | str) -> dict | list | None:
        """Try to parse body as JSON, returning None if it fails."""
        try:
            if isinstance(body, bytes):
                body = body.decode("utf-8")
            return json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _url_matches(self, url: str, pattern: str) -> bool:
        """Check if URL matches a glob pattern."""
        import fnmatch
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path

        # Handle ** prefix (match any domain)
        if pattern.startswith("**/"):
            pattern = pattern[3:]
            return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(
                path.lstrip("/"), pattern
            )

        # Full URL pattern
        return fnmatch.fnmatch(url, pattern)

    def _evaluate_condition(self, condition: str, context: dict) -> bool:
        """Evaluate a JSONata-like condition."""
        result = evaluate_expression(condition, context)
        return bool(result)

    def _extract_detection_fields(
        self,
        data: Any,
        extract_config: dict[str, str],
        context: PipelineContext,
    ) -> dict[str, Any]:
        """Extract fields using JSONata expressions."""
        extracted: dict[str, Any] = {}

        # Build evaluation context
        if isinstance(data, dict):
            eval_context = {"response": data, "request": context.request_data}
        else:
            eval_context = {"response": data, "request": context.request_data}

        for field_path, expr in extract_config.items():
            try:
                value = evaluate_expression(expr, eval_context)
                if value is not None:
                    extracted[field_path] = value
            except Exception as e:
                logger.debug(f"Failed to extract {field_path}: {e}")

        return extracted

    def _merge_extracted(
        self, target: dict[str, Any], source: dict[str, Any]
    ) -> None:
        """
        Merge extracted fields into target, organizing by path prefix.

        Paths like "user.email" become {"user": {"email": ...}}
        """
        for path, value in source.items():
            parts = path.split(".")
            current = target

            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            current[parts[-1]] = value

    def _deep_merge(self, target: dict, source: dict) -> None:
        """Deep merge source into target."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value


# Global instance
_processor: DetectionProcessor | None = None


def get_detection_processor() -> DetectionProcessor:
    """Get the global detection processor instance."""
    global _processor
    if _processor is None:
        _processor = DetectionProcessor()
    return _processor
