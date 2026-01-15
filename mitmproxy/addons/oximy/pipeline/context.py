"""
Pipeline context for passing data through processing stages.

PipelineContext holds:
- Raw request/response bytes
- Parsed request/response data
- Headers
- Accumulated state for streaming responses
- Extracted fields
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from typing import Any


@dataclass
class PipelineContext:
    """
    Context passed through pipeline operations.

    Holds both raw bytes and parsed data for request and response,
    plus accumulated state for streaming operations.
    """

    # Raw bytes
    request_body: bytes | None = None
    response_body: bytes | None = None

    # Headers (lowercase keys)
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)

    # Parsed data (populated by parse operations)
    request_data: Any = None
    response_data: Any = None

    # Accumulated state (populated by stream/accumulate operations)
    accumulated: dict[str, Any] = field(default_factory=dict)

    # Extracted fields (populated by extract operations)
    extracted: dict[str, Any] = field(default_factory=dict)

    # Stream chunks for streaming responses
    stream_chunks: list[dict] = field(default_factory=list)

    # Error state
    error: str | None = None

    # URL and method for context
    url: str | None = None
    method: str | None = None
    status_code: int | None = None

    @classmethod
    def from_flow(cls, flow: Any) -> PipelineContext:
        """
        Create a PipelineContext from a mitmproxy flow.

        Args:
            flow: mitmproxy HTTP flow object

        Returns:
            PipelineContext with request/response data
        """
        request_headers = {}
        response_headers = {}

        if flow.request:
            for key, value in flow.request.headers.items():
                request_headers[key.lower()] = value

        if flow.response:
            for key, value in flow.response.headers.items():
                response_headers[key.lower()] = value

        return cls(
            request_body=flow.request.content if flow.request else None,
            response_body=flow.response.content if flow.response else None,
            request_headers=request_headers,
            response_headers=response_headers,
            url=flow.request.pretty_url if flow.request else None,
            method=flow.request.method if flow.request else None,
            status_code=flow.response.status_code if flow.response else None,
        )

    def get_header(self, name: str, from_request: bool = True) -> str | None:
        """Get a header value (case-insensitive)."""
        headers = self.request_headers if from_request else self.response_headers
        return headers.get(name.lower())

    def get_content_type(self, from_request: bool = False) -> str | None:
        """Get the content-type header."""
        return self.get_header("content-type", from_request)

    def is_streaming_response(self) -> bool:
        """Check if response appears to be streaming (SSE, NDJSON, etc.)."""
        content_type = self.get_content_type(from_request=False)
        if not content_type:
            return False

        streaming_types = [
            "text/event-stream",
            "application/x-ndjson",
            "application/stream+json",
            "application/json+stream",
        ]
        return any(st in content_type for st in streaming_types)

    def set_error(self, message: str) -> None:
        """Set an error message."""
        self.error = message

    def has_error(self) -> bool:
        """Check if an error occurred."""
        return self.error is not None

    def merge_extracted(self, new_fields: dict[str, Any]) -> None:
        """Merge new extracted fields into the context."""
        self.extracted.update(new_fields)

    def get_extracted(self, key: str, default: Any = None) -> Any:
        """Get an extracted field value."""
        return self.extracted.get(key, default)

    def to_extract_context(self) -> dict[str, Any]:
        """
        Build context dict for JSONata extraction.

        Provides special variables:
        - $request: parsed request data
        - $response: parsed response data
        - $accumulated: accumulated streaming data
        - $headers: combined headers
        """
        return {
            "request": self.request_data,
            "response": self.response_data,
            "accumulated": self.accumulated,
            "headers": {
                "request": self.request_headers,
                "response": self.response_headers,
            },
        }
