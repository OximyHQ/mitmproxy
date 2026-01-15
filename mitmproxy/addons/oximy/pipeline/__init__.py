"""
Pipeline package for config-driven request/response processing.

This package implements the pipeline operations defined in tool-config.schema.json:
- decode: Base64, gzip, deflate, br, zstd, hex decoding
- parse: JSON, XML, form, multipart, GraphQL, JWT parsing
- stream: SSE, NDJSON, WebSocket, chunked, gRPC streaming
- accumulate: Conditional extraction and field accumulation
- extract_auth: JWT decoding, bearer token extraction
- extract_headers: Header extraction
- branch: Conditional branching based on data content
- transform: Reserved for future transformations
"""

from mitmproxy.addons.oximy.pipeline.context import PipelineContext
from mitmproxy.addons.oximy.pipeline.executor import Pipeline

__all__ = ["Pipeline", "PipelineContext"]
