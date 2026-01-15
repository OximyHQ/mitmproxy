"""
Core type definitions for the Oximy addon.

Models conform strictly to:
- trace-output.schema.json for output events (TraceOutput)
- tool-config.schema.json for config structures
"""

from __future__ import annotations

import random
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from datetime import timezone
from typing import Any
from typing import Literal
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.process import ClientProcess


# =============================================================================
# Match Result (internal use during flow processing)
# =============================================================================


@dataclass
class MatchResult:
    """Result of matching a flow against the OISP bundle."""

    # Classifications:
    # - full_extraction: Feature endpoint (role: both), emit event with full content
    # - feature_extraction: Feature endpoint (role: detect), emit event with metadata
    # - detection_cache: Detection source match, cache context silently (no event)
    # - metadata_only: Known tool but no feature/detection match, emit 1 per tool per day
    # - drop: Unknown tool, don't emit
    classification: Literal["full_extraction", "feature_extraction", "detection_cache", "metadata_only", "drop"]
    source_type: Literal["api", "direct_api", "app", "website"] | None = None
    source_id: str | None = None  # "openai", "cursor", "chatgpt"
    provider_id: str | None = None  # "openai", "anthropic"
    api_format: str | None = None  # "openai", "anthropic", "google"
    endpoint: str | None = None  # "chat", "voice", etc.
    feature_type: str | None = None  # "chat", "asset_creation", "codegen", etc.
    feature_key: str | None = None  # The feature key from config (e.g., "platform_creation")


# =============================================================================
# Domain Pattern (internal use for domain matching)
# =============================================================================


@dataclass
class DomainPattern:
    """A compiled regex pattern for matching dynamic domains."""

    pattern: str
    compiled: object  # re.Pattern
    provider_id: str


# =============================================================================
# TraceOutput Models - Conforming to trace-output.schema.json
# =============================================================================


@dataclass
class EventSource:
    """
    Source information for an event.

    Required: type, tool_id, feature
    """

    type: Literal["app", "website"]
    tool_id: str
    feature: str
    tool_name: str | None = None
    vendor: str | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {
            "type": self.type,
            "tool_id": self.tool_id,
            "feature": self.feature,
        }
        if self.tool_name:
            result["tool_name"] = self.tool_name
        if self.vendor:
            result["vendor"] = self.vendor
        return result


@dataclass
class Transport:
    """
    Network transport details.

    All fields optional per schema.
    """

    protocol: Literal["http", "https", "ws", "wss", "grpc"] | None = None
    method: str | None = None
    url: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    referer: str | None = None
    origin: str | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {}
        if self.protocol:
            result["protocol"] = self.protocol
        if self.method:
            result["method"] = self.method
        if self.url:
            result["url"] = self.url
        if self.status_code is not None:
            result["status_code"] = self.status_code
        if self.content_type:
            result["content_type"] = self.content_type
        if self.referer:
            result["referer"] = self.referer
        if self.origin:
            result["origin"] = self.origin
        return result


@dataclass
class EventTiming:
    """
    Request timing information.

    All fields optional per schema.
    """

    started_at: str | None = None
    duration_ms: int | None = None
    ttfb_ms: int | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {}
        if self.started_at:
            result["started_at"] = self.started_at
        if self.duration_ms is not None:
            result["duration_ms"] = self.duration_ms
        if self.ttfb_ms is not None:
            result["ttfb_ms"] = self.ttfb_ms
        return result


@dataclass
class ClientInfo:
    """
    Client process information for apps/CLI tools.

    All fields optional per schema.
    """

    pid: int | None = None
    name: str | None = None
    path: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    wrapper: dict | None = None  # {pid, name, bundle_id}
    user: str | None = None
    tool_id: str | None = None
    port: int | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {}
        if self.pid is not None:
            result["pid"] = self.pid
        if self.name:
            result["name"] = self.name
        if self.path:
            result["path"] = self.path
        if self.parent_pid is not None:
            result["parent_pid"] = self.parent_pid
        if self.parent_name:
            result["parent_name"] = self.parent_name
        if self.wrapper:
            result["wrapper"] = self.wrapper
        if self.user:
            result["user"] = self.user
        if self.tool_id:
            result["tool_id"] = self.tool_id
        if self.port is not None:
            result["port"] = self.port
        return result

    @classmethod
    def from_client_process(cls, process: ClientProcess) -> ClientInfo:
        """Create ClientInfo from a ClientProcess."""
        # Note: ClientProcess doesn't have wrapper fields yet
        # When wrapper support is added, update this method
        return cls(
            pid=process.pid,
            name=process.name,
            path=process.path,
            parent_pid=process.ppid,  # ClientProcess uses ppid
            parent_name=process.parent_name,
            wrapper=None,  # Not available in current ClientProcess
            user=process.user,
            tool_id=process.id,  # ClientProcess uses id
            port=process.port,
        )


@dataclass
class InteractionInput:
    """
    Input/request data for an interaction.

    All fields optional per schema.
    """

    text: str | None = None
    files: list[dict] | None = None  # [{name, type, size, id}]
    context: str | dict | None = None
    parameters: dict | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {}
        if self.text is not None:
            result["text"] = self.text
        if self.files:
            result["files"] = self.files
        if self.context is not None:
            result["context"] = self.context
        if self.parameters:
            result["parameters"] = self.parameters
        return result


@dataclass
class InteractionOutput:
    """
    Output/response data for an interaction.

    All fields optional per schema.
    """

    text: str | None = None
    thinking: str | None = None
    artifacts: list[dict] | None = None  # [{type, url, content, filename, metadata}]
    actions: list[dict] | None = None  # [{type, detail}]
    tool_calls: list[dict] | None = None  # [{name, arguments, result}]
    citations: list[dict] | None = None  # [{url, title, snippet}]

    def to_dict(self) -> dict:
        result: dict[str, Any] = {}
        if self.text is not None:
            result["text"] = self.text
        if self.thinking is not None:
            result["thinking"] = self.thinking
        if self.artifacts:
            result["artifacts"] = self.artifacts
        if self.actions:
            result["actions"] = self.actions
        if self.tool_calls:
            result["tool_calls"] = self.tool_calls
        if self.citations:
            result["citations"] = self.citations
        return result


@dataclass
class Interaction:
    """
    The AI interaction data.

    Required: type
    Type must be one of: chat, codegen, asset_creation, text_manipulation, platform_output, other
    """

    type: Literal["chat", "codegen", "asset_creation", "text_manipulation", "platform_output", "other"]
    name: str | None = None
    input: InteractionInput | None = None
    output: InteractionOutput | None = None
    model: str | None = None
    conversation_id: str | None = None
    message_id: str | None = None
    turn_index: int | None = None
    capabilities: list[str] | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {"type": self.type}
        if self.name:
            result["name"] = self.name
        if self.input:
            result["input"] = self.input.to_dict()
        if self.output:
            result["output"] = self.output.to_dict()
        if self.model:
            result["model"] = self.model
        if self.conversation_id:
            result["conversation_id"] = self.conversation_id
        if self.message_id:
            result["message_id"] = self.message_id
        if self.turn_index is not None:
            result["turn_index"] = self.turn_index
        if self.capabilities:
            result["capabilities"] = self.capabilities
        return result


@dataclass
class Usage:
    """
    Token/resource usage.

    All fields optional per schema.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    cost_usd: float | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {}
        if self.input_tokens is not None:
            result["input_tokens"] = self.input_tokens
        if self.output_tokens is not None:
            result["output_tokens"] = self.output_tokens
        if self.total_tokens is not None:
            result["total_tokens"] = self.total_tokens
        if self.cost_usd is not None:
            result["cost_usd"] = self.cost_usd
        return result


@dataclass
class ErrorInfo:
    """
    Error information if request failed.

    All fields optional per schema.
    """

    code: str | None = None
    message: str | None = None
    status: int | None = None

    def to_dict(self) -> dict:
        result: dict[str, Any] = {}
        if self.code:
            result["code"] = self.code
        if self.message:
            result["message"] = self.message
        if self.status is not None:
            result["status"] = self.status
        return result


@dataclass
class TraceOutput:
    """
    An OISP trace event representing an AI interaction.

    This is the primary output format written to JSONL files.
    Conforms exactly to trace-output.schema.json.

    Required: event_id, timestamp, source, trace_level, interaction
    """

    # Required fields
    event_id: str
    timestamp: str
    source: EventSource
    trace_level: Literal["full_extraction", "feature_extraction", "metadata_only", "error"]
    interaction: Interaction

    # Optional fields
    parent_event_id: str | None = None
    transport: Transport | None = None
    timing: EventTiming | None = None
    client: ClientInfo | None = None
    usage: Usage | None = None
    context: dict | None = None  # Flexible: subscription, user, org, rate_limit, etc.
    error: ErrorInfo | None = None
    meta: dict | None = None
    _raw: dict | None = None  # {request: {...}, response: {...}}

    @classmethod
    def create(
        cls,
        source: EventSource,
        trace_level: Literal["full_extraction", "feature_extraction", "metadata_only", "error"],
        interaction: Interaction,
        parent_event_id: str | None = None,
        transport: Transport | None = None,
        timing: EventTiming | None = None,
        client: ClientInfo | None = None,
        usage: Usage | None = None,
        context: dict | None = None,
        error: ErrorInfo | None = None,
        meta: dict | None = None,
        raw: dict | None = None,
    ) -> TraceOutput:
        """Create a new trace event with auto-generated ID and timestamp."""
        event_id = _generate_uuid7()
        timestamp = (
            datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )

        return cls(
            event_id=event_id,
            timestamp=timestamp,
            source=source,
            trace_level=trace_level,
            interaction=interaction,
            parent_event_id=parent_event_id,
            transport=transport,
            timing=timing,
            client=client,
            usage=usage,
            context=context,
            error=error,
            meta=meta,
            _raw=raw,
        )

    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON output."""
        result: dict[str, Any] = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source": self.source.to_dict(),
            "trace_level": self.trace_level,
            "interaction": self.interaction.to_dict(),
        }

        if self.parent_event_id:
            result["parent_event_id"] = self.parent_event_id
        if self.transport:
            result["transport"] = self.transport.to_dict()
        if self.timing:
            result["timing"] = self.timing.to_dict()
        if self.client:
            result["client"] = self.client.to_dict()
        if self.usage:
            result["usage"] = self.usage.to_dict()
        if self.context:
            result["context"] = self.context
        if self.error:
            result["error"] = self.error.to_dict()
        if self.meta:
            result["meta"] = self.meta
        if self._raw:
            result["_raw"] = self._raw

        return result


# =============================================================================
# Utility Functions
# =============================================================================


def _generate_uuid7() -> str:
    """Generate a UUID v7 (time-sortable) or fall back to v4."""
    # UUID v7: timestamp (48 bits) + version (4 bits) + random (12 bits) + variant (2 bits) + random (62 bits)
    timestamp_ms = int(time.time() * 1000)
    timestamp_bytes = timestamp_ms.to_bytes(6, "big")

    # Random bytes for the rest
    rand_bytes = random.getrandbits(74)

    # Construct UUID v7
    uuid_int = (
        (int.from_bytes(timestamp_bytes, "big") << 80)
        | (0x7 << 76)  # version 7
        | ((rand_bytes >> 62) << 64)
        | (0x2 << 62)  # variant
        | (rand_bytes & ((1 << 62) - 1))
    )

    return str(uuid.UUID(int=uuid_int))
