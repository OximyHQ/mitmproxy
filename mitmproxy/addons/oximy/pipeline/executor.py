"""
Pipeline executor that processes data through a series of operations.

The Pipeline class:
1. Takes a list of operation configs from tool-config.schema.json
2. Executes each operation in order
3. Passes PipelineContext through each stage
4. Returns the final context with parsed/extracted data
"""

from __future__ import annotations

import logging
from typing import Callable

from mitmproxy.addons.oximy.pipeline.context import PipelineContext
from mitmproxy.addons.oximy.pipeline.operations import accumulate_op
from mitmproxy.addons.oximy.pipeline.operations import branch_op
from mitmproxy.addons.oximy.pipeline.operations import decode_op
from mitmproxy.addons.oximy.pipeline.operations import extract_auth_op
from mitmproxy.addons.oximy.pipeline.operations import extract_headers_op
from mitmproxy.addons.oximy.pipeline.operations import parse_op
from mitmproxy.addons.oximy.pipeline.operations import stream_op

logger = logging.getLogger(__name__)


# Operation registry: op_name -> handler function
OPERATIONS: dict[str, Callable[[PipelineContext, dict], PipelineContext]] = {
    "decode": decode_op,
    "parse": parse_op,
    "stream": stream_op,
    "accumulate": accumulate_op,
    "extract_auth": extract_auth_op,
    "extract_headers": extract_headers_op,
    "branch": branch_op,
    # "transform" is reserved for future use
}


class Pipeline:
    """
    Executes a sequence of pipeline operations on request/response data.

    Operations are defined in tool-config.schema.json and include:
    - decode: Decode encoded data (base64, gzip, etc.)
    - parse: Parse data formats (JSON, form, GraphQL, etc.)
    - stream: Handle streaming responses (SSE, NDJSON, etc.)
    - accumulate: Accumulate data from streaming chunks
    - extract_auth: Extract authentication information
    - extract_headers: Extract specific headers
    - branch: Conditional branching based on data
    """

    def __init__(self, operations: list[dict]):
        """
        Initialize pipeline with operation configs.

        Args:
            operations: List of operation dicts from config, e.g.:
                [
                    {"op": "parse", "format": "json", "apply_to": "request"},
                    {"op": "stream", "transport": "sse", "apply_to": "response"},
                    {"op": "accumulate", "rules": [...], "fields": {...}}
                ]
        """
        self.operations = operations

    def execute(self, context: PipelineContext) -> PipelineContext:
        """
        Execute all pipeline operations on the context.

        Args:
            context: PipelineContext with request/response data

        Returns:
            Updated PipelineContext with parsed/extracted data
        """
        for op_config in self.operations:
            op_name = op_config.get("op")
            if not op_name:
                logger.warning("Pipeline operation missing 'op' field")
                continue

            handler = OPERATIONS.get(op_name)
            if not handler:
                if op_name == "transform":
                    logger.debug("Transform operation not yet implemented")
                else:
                    logger.warning(f"Unknown pipeline operation: {op_name}")
                continue

            try:
                context = handler(context, op_config)

                # Stop pipeline if error occurred
                if context.has_error():
                    logger.warning(f"Pipeline stopped due to error: {context.error}")
                    break

            except Exception as e:
                logger.error(f"Pipeline operation '{op_name}' failed: {e}")
                context.set_error(f"{op_name} failed: {e}")
                break

        return context

    @classmethod
    def from_endpoint_config(cls, endpoint: dict) -> Pipeline | None:
        """
        Create a Pipeline from an endpoint configuration.

        Args:
            endpoint: Endpoint dict from tool config with optional 'pipeline' key

        Returns:
            Pipeline instance or None if no pipeline defined
        """
        pipeline_ops = endpoint.get("pipeline")
        if not pipeline_ops:
            return None
        return cls(pipeline_ops)


def execute_pipeline(
    context: PipelineContext,
    operations: list[dict],
) -> PipelineContext:
    """
    Convenience function to execute pipeline operations.

    Args:
        context: PipelineContext with request/response data
        operations: List of operation configs

    Returns:
        Updated PipelineContext
    """
    pipeline = Pipeline(operations)
    return pipeline.execute(context)
