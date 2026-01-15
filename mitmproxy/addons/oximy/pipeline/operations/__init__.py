"""
Pipeline operations for data processing.

Each operation takes a PipelineContext and config dict,
performs its transformation, and returns the updated context.
"""

from mitmproxy.addons.oximy.pipeline.operations.accumulate import accumulate_op
from mitmproxy.addons.oximy.pipeline.operations.branch import branch_op
from mitmproxy.addons.oximy.pipeline.operations.decode import decode_op
from mitmproxy.addons.oximy.pipeline.operations.extract_auth import extract_auth_op
from mitmproxy.addons.oximy.pipeline.operations.extract_headers import (
    extract_headers_op,
)
from mitmproxy.addons.oximy.pipeline.operations.parse import parse_op
from mitmproxy.addons.oximy.pipeline.operations.stream import stream_op

__all__ = [
    "decode_op",
    "parse_op",
    "stream_op",
    "accumulate_op",
    "extract_auth_op",
    "extract_headers_op",
    "branch_op",
]
