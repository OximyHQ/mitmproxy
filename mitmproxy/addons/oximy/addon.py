"""
Main Oximy addon for mitmproxy.

Captures AI API traffic based on OISP bundle whitelists,
normalizes events, and writes to JSONL files.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.addons.oximy.bundle import BundleLoader
from mitmproxy.addons.oximy.bundle import DEFAULT_BUNDLE_URL
from mitmproxy.addons.oximy.config import config
from mitmproxy.addons.oximy.config_registry import ConfigRegistry
from mitmproxy.addons.oximy.detection import get_detection_processor
from mitmproxy.addons.oximy.models import ClientInfo
from mitmproxy.addons.oximy.models import EventSource
from mitmproxy.addons.oximy.models import EventTiming
from mitmproxy.addons.oximy.models import Interaction
from mitmproxy.addons.oximy.models import InteractionInput
from mitmproxy.addons.oximy.models import InteractionOutput
from mitmproxy.addons.oximy.models import MatchResult
from mitmproxy.addons.oximy.models import TraceOutput
from mitmproxy.addons.oximy.models import Transport
from mitmproxy.addons.oximy.models import Usage
from mitmproxy.addons.oximy.passthrough import TLSPassthrough
from mitmproxy.addons.oximy.pipeline import Pipeline
from mitmproxy.addons.oximy.pipeline.context import PipelineContext
from mitmproxy.addons.oximy.pipeline.extractors import extract_fields
from mitmproxy.addons.oximy.process import ClientProcess
from mitmproxy.addons.oximy.process import ProcessResolver
from mitmproxy.addons.oximy.writer import EventWriter

if TYPE_CHECKING:
    from mitmproxy.addons.oximy.bundle import OISPBundle

# Configure logging to output to stderr (which will be captured by MITMService)
# Set INFO level by default so we can see what's happening
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)

logger = logging.getLogger(__name__)


class _SuppressDisconnectFilter(logging.Filter):
    """Filter out noisy 'client disconnect' and 'server disconnect' messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        # Suppress generic disconnect messages (but keep TLS failure messages)
        if (
            msg == "client disconnect"
            or msg.startswith("server disconnect ")
            or msg.startswith("client connect")
            or msg.startswith("server connect")
        ):
            return False
        return True


# Apply filter to mitmproxy's proxy logger
logging.getLogger("mitmproxy.proxy.server").addFilter(_SuppressDisconnectFilter())

# Metadata keys for storing data on flows
OXIMY_METADATA_KEY = "oximy_match"
OXIMY_CLIENT_KEY = "oximy_client"

# -------------------------------------------------------------------------
# System Proxy Configuration
# Controlled by config module (env var OXIMY_AUTO_PROXY or ~/.oximy/dev.json)
# Production default: False (proxy managed externally)
# Development default: True (auto-configure for convenience)
# -------------------------------------------------------------------------
OXIMY_AUTO_PROXY_ENABLED = config.AUTO_PROXY_ENABLED
OXIMY_PROXY_HOST = config.PROXY_HOST
OXIMY_PROXY_PORT = config.PROXY_PORT
OXIMY_NETWORK_SERVICE = "Wi-Fi"  # macOS: Change if using different network interface


def _set_system_proxy(enable: bool) -> None:
    """
    Enable or disable system proxy settings (cross-platform).

    This is a development convenience - set OXIMY_AUTO_PROXY_ENABLED=False
    for production deployments where proxy should be managed externally.
    """
    if not OXIMY_AUTO_PROXY_ENABLED:
        return

    if sys.platform == "darwin":
        _set_macos_proxy(enable)
    elif sys.platform == "win32":
        _set_windows_proxy(enable)
    else:
        logger.debug("Auto proxy configuration not supported on this platform")


def _set_windows_proxy(enable: bool) -> None:
    """
    Enable or disable Windows system proxy settings via registry.

    Modifies Internet Settings in the Windows registry to set/unset
    the system-wide HTTP/HTTPS proxy.
    """
    import winreg

    INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    proxy_server = f"{OXIMY_PROXY_HOST}:{OXIMY_PROXY_PORT}"

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS, 0, winreg.KEY_WRITE
        ) as key:
            if enable:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
                print(f"[Oximy] Windows system proxy enabled: {proxy_server}")
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                print("[Oximy] Windows system proxy disabled")
    except OSError as e:
        print(f"[Oximy] Failed to set Windows proxy: {e}")


def _set_macos_proxy(enable: bool) -> None:
    """
    Enable or disable macOS system proxy settings.
    """
    try:
        if enable:
            # Enable HTTPS proxy
            subprocess.run(
                [
                    "networksetup",
                    "-setsecurewebproxy",
                    OXIMY_NETWORK_SERVICE,
                    OXIMY_PROXY_HOST,
                    OXIMY_PROXY_PORT,
                ],
                check=True,
                capture_output=True,
            )
            # Enable HTTP proxy
            subprocess.run(
                [
                    "networksetup",
                    "-setwebproxy",
                    OXIMY_NETWORK_SERVICE,
                    OXIMY_PROXY_HOST,
                    OXIMY_PROXY_PORT,
                ],
                check=True,
                capture_output=True,
            )
            logger.info(f"macOS system proxy enabled: {OXIMY_PROXY_HOST}:{OXIMY_PROXY_PORT}")
        else:
            # Disable HTTPS proxy
            subprocess.run(
                [
                    "networksetup",
                    "-setsecurewebproxystate",
                    OXIMY_NETWORK_SERVICE,
                    "off",
                ],
                check=True,
                capture_output=True,
            )
            # Disable HTTP proxy
            subprocess.run(
                ["networksetup", "-setwebproxystate", OXIMY_NETWORK_SERVICE, "off"],
                check=True,
                capture_output=True,
            )
            logger.info("macOS system proxy disabled")
    except subprocess.CalledProcessError as e:
        logger.warning(
            f"Failed to {'enable' if enable else 'disable'} macOS system proxy: {e}"
        )
    except FileNotFoundError:
        logger.warning("networksetup command not found - not on macOS?")


class OximyAddon:
    """
    Mitmproxy addon that captures AI API traffic.

    Usage:
        mitmdump -s path/to/oximy/__init__.py --set oximy_enabled=true

    Or load programmatically:
        from mitmproxy.addons.oximy import OximyAddon
        addons = [OximyAddon()]
    """

    def __init__(self):
        self._bundle_loader: BundleLoader | None = None
        self._bundle: OISPBundle | None = None
        self._config_registry: ConfigRegistry | None = None
        self._writer: EventWriter | None = None
        self._process_resolver: ProcessResolver | None = None
        self._tls_passthrough: TLSPassthrough | None = None
        self._stream_buffers: dict[str, PipelineContext] = {}
        self._enabled: bool = False
        # Track tools that have emitted events today (per-day deduplication)
        # - _emitted_feature_tools: tools that emitted full_extraction or feature_extraction
        # - _emitted_metadata_tools: tools that emitted metadata_only (when no feature available)
        # Reset on day change (checked via _current_day)
        self._emitted_feature_tools: set[str] = set()
        self._emitted_metadata_tools: set[str] = set()
        self._current_day: str | None = None  # "YYYY-MM-DD" format

    def _check_day_reset(self) -> None:
        """Reset per-day tracking if the day has changed."""
        from datetime import date
        today = date.today().isoformat()  # "YYYY-MM-DD"
        if self._current_day != today:
            if self._current_day is not None:
                logger.info(f"Day changed from {self._current_day} to {today}, resetting tracking")
            self._current_day = today
            self._emitted_feature_tools.clear()
            self._emitted_metadata_tools.clear()
            # Also clear any stale detection context
            get_detection_processor().clear_context()

    def _deep_merge(self, target: dict, source: dict) -> None:
        """Deep merge source into target dict."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value

    def load(self, loader) -> None:
        """Register addon options."""
        loader.add_option(
            name="oximy_enabled",
            typespec=bool,
            default=False,
            help="Enable OISP traffic capture",
        )
        loader.add_option(
            name="oximy_output_dir",
            typespec=str,
            default="~/.oximy/traces",
            help="Directory for output JSONL files",
        )
        loader.add_option(
            name="oximy_bundle_url",
            typespec=str,
            default=DEFAULT_BUNDLE_URL,
            help="URL of the OISP bundle JSON",
        )
        loader.add_option(
            name="oximy_bundle_refresh_hours",
            typespec=int,
            default=24,
            help="Bundle refresh interval in hours",
        )
        loader.add_option(
            name="oximy_include_raw",
            typespec=bool,
            default=True,
            help="Include raw request/response bodies in events",
        )
        loader.add_option(
            name="oximy_verbose",
            typespec=bool,
            default=False,
            help="Enable verbose/debug logging for troubleshooting",
        )
        loader.add_option(
            name="oximy_target_id",
            typespec=str,
            default="",
            help="Only capture traffic for this specific app/website ID (e.g., 'granola', 'chatgpt')",
        )
        loader.add_option(
            name="oximy_test_mode",
            typespec=bool,
            default=False,
            help="Test mode: write pretty JSON to test_trace.json (overwrites each run)",
        )
        loader.add_option(
            name="oximy_validate",
            typespec=bool,
            default=False,
            help="Validate output events against trace-output.schema.json",
        )

    def configure(self, updated: set[str]) -> None:
        """Handle configuration changes."""
        # Handle verbose logging toggle
        if "oximy_verbose" in updated:
            if ctx.options.oximy_verbose:
                logging.getLogger("mitmproxy.addons.oximy").setLevel(logging.DEBUG)
                logger.info("Verbose logging ENABLED")
            else:
                logging.getLogger("mitmproxy.addons.oximy").setLevel(logging.INFO)

        # Check if we need to (re)initialize
        relevant_options = {"oximy_enabled", "oximy_bundle_url", "oximy_output_dir", "oximy_test_mode", "oximy_target_id", "oximy_validate"}
        if not relevant_options.intersection(updated):
            return

        new_enabled = ctx.options.oximy_enabled
        logger.info(f"Oximy configure: oximy_enabled={new_enabled}")

        # Handle disable
        if not new_enabled:
            if self._enabled:
                logger.info("Oximy addon disabled")
                self._cleanup()
            self._enabled = False
            return

        self._enabled = True

        # Initialize bundle loader
        self._bundle_loader = BundleLoader(
            bundle_url=ctx.options.oximy_bundle_url,
            max_age_hours=ctx.options.oximy_bundle_refresh_hours,
        )

        try:
            self._bundle = self._bundle_loader.load()
            logger.info("========== OXIMY ADDON STARTING ==========")
            logger.info(f"OISP Bundle loaded: version {self._bundle.bundle_version}")
            logger.info(f"  - Websites: {len(self._bundle.websites)} sites")
            logger.info(f"  - Apps: {len(self._bundle.apps)} applications")
        except RuntimeError as e:
            logger.error("========== OXIMY ADDON FAILED TO START ==========")
            logger.error(f"Failed to load OISP bundle: {e}")
            logger.error(f"Bundle URL: {ctx.options.oximy_bundle_url}")
            logger.error("The addon will be DISABLED - no AI traffic will be captured!")
            self._enabled = False
            return
        except Exception as e:
            logger.error("========== OXIMY ADDON FAILED TO START ==========")
            logger.error(f"Unexpected error loading bundle: {e}", exc_info=True)
            self._enabled = False
            return

        # Initialize config registry
        self._config_registry = ConfigRegistry()
        self._config_registry.load_from_bundle({
            "registry": {
                "apps": self._bundle.apps,
                "websites": self._bundle.websites,
            }
        })

        # Initialize writer
        output_dir = Path(ctx.options.oximy_output_dir).expanduser()
        test_mode = ctx.options.oximy_test_mode
        validate = ctx.options.oximy_validate
        self._writer = EventWriter(output_dir, test_mode=test_mode, validate=validate)

        # Initialize process resolver for client attribution
        self._process_resolver = ProcessResolver()

        # Build bundle_id -> app_id index from registry
        bundle_id_index = self._config_registry.build_bundle_id_to_app_id_index()
        self._process_resolver.set_bundle_id_index(bundle_id_index)
        if bundle_id_index:
            logger.info(f"  - Bundle ID index: {len(bundle_id_index)} mappings")

        # Initialize TLS passthrough for certificate-pinned hosts
        passthrough_cache = output_dir / "pinned_hosts.json"
        self._tls_passthrough = TLSPassthrough(persist_path=passthrough_cache)
        self._tls_passthrough.set_process_resolver(self._process_resolver)

        # Enable system proxy (development convenience)
        _set_system_proxy(enable=True)

        logger.info(f"Output directory: {output_dir}")

        # Log test mode and target filter settings
        target_id = ctx.options.oximy_target_id
        if test_mode:
            logger.info("TEST MODE: Writing to test_trace.json (pretty JSON, overwrites)")
        if target_id:
            logger.info(f"TARGET FILTER: Only capturing traffic for '{target_id}'")
        if validate:
            logger.info("VALIDATION: Output events will be validated against schema")

        logger.info("========== OXIMY ADDON READY ==========")
        logger.info("Listening for AI traffic...")

    async def request(self, flow: http.HTTPFlow) -> None:
        """Classify incoming requests and capture client process info."""
        if not self._enabled or not self._config_registry:
            return

        try:
            # Capture client process info FIRST, before matching
            # This must happen as early as possible to avoid race conditions
            # where the client process exits before we can query it
            # Also needed for app matching which requires process info
            client_process: ClientProcess | None = None
            if self._process_resolver:
                try:
                    client_port = flow.client_conn.peername[1]
                    client_process = await self._process_resolver.get_process_for_port(
                        client_port
                    )
                    flow.metadata[OXIMY_CLIENT_KEY] = client_process
                except Exception as e:
                    logger.debug(f"Could not resolve client process: {e}")

            # Match the flow using config registry
            match_result = self._match_flow(flow, client_process)

            # Store result in flow metadata
            flow.metadata[OXIMY_METADATA_KEY] = match_result

            if match_result.classification != "drop":
                if client_process:
                    logger.debug(
                        f"Client process: {client_process.name} (PID {client_process.pid})"
                    )
                logger.debug(
                    f"Matched: {flow.request.pretty_host} -> "
                    f"{match_result.classification} ({match_result.source_type}/{match_result.source_id})"
                )
        except Exception as e:
            logger.error(
                f"Error in request hook for {flow.request.pretty_host}: {e}",
                exc_info=True,
            )

    def _match_flow(
        self, flow: http.HTTPFlow, client_process: ClientProcess | None
    ) -> MatchResult:
        """
        Match a flow against the config registry.

        Priority order for each config:
        1. Feature endpoint match -> full_extraction
        2. Detection source match -> detection_cache (silent caching)
        3. Known tool domain match -> metadata_only
        4. Unknown -> drop
        """
        if not self._config_registry:
            return MatchResult(classification="drop")

        domain = flow.request.pretty_host
        url = flow.request.pretty_url
        method = flow.request.method

        # logger.debug(f"_match_flow: domain={domain}, url={url}, method={method}")

        # Try to match as website by domain
        website_config = self._config_registry.get_for_domain(domain)
        logger.debug(f"_match_flow: website_config for {domain} = {website_config.get('id') if website_config else None}")
        if website_config:
            return self._match_against_config(website_config, url, method, "website")

        # Try to match as app by API domain
        app_config = self._config_registry.get_for_api_domain(domain)
        if app_config:
            return self._match_against_config(app_config, url, method, "app")

        # Try to match app by client process (bundle ID or exe name)
        if client_process:
            bundle_id = client_process.bundle_id
            if bundle_id:
                app_config = self._config_registry.get_for_bundle_id(bundle_id)
                if app_config:
                    # Only process if domain is in api_domains
                    api_domains = app_config.get("api_domains", [])
                    if domain in api_domains:
                        return self._match_against_config(app_config, url, method, "app")
                    # Domain not in api_domains - drop this traffic
                    logger.debug(f"Dropping {domain} from {app_config.get('id')} - not in api_domains")

        # No match - drop
        return MatchResult(classification="drop")

    def _match_against_config(
        self, config: dict, url: str, method: str, source_type: str
    ) -> MatchResult:
        """
        Match a URL against a config's features and detection sources.

        Priority:
        1. Feature endpoint -> full_extraction (or feature_extraction for detect-only)
        2. Detection source -> detection_cache
        3. Fallback -> metadata_only
        """
        if not self._config_registry:
            return MatchResult(classification="drop")

        source_id = config.get("id")

        # 1. Try to match a feature endpoint first
        feature_match = self._config_registry.match_url(url, config, method)
        if feature_match:
            feature_key, endpoint_config = feature_match
            feature = config.get("features", {}).get(feature_key, {})
            # Check endpoint role to determine classification
            endpoint_role = endpoint_config.get("role", "both")
            classification = "feature_extraction" if endpoint_role == "detect" else "full_extraction"
            return MatchResult(
                classification=classification,  # type: ignore
                source_type=source_type,  # type: ignore
                source_id=source_id,
                endpoint=feature_key,
                feature_type=feature.get("type", "other"),
                feature_key=feature_key,
            )

        # 2. Try to match a detection source (silent caching)
        detection_match = self._config_registry.match_detection_source(url, config, method)
        if detection_match:
            detection_id = detection_match.get("id", "unknown")
            return MatchResult(
                classification="detection_cache",
                source_type=source_type,  # type: ignore
                source_id=source_id,
                endpoint=f"detection:{detection_id}",
            )

        # 3. Fallback - known tool but no specific match
        return MatchResult(
            classification="metadata_only",
            source_type=source_type,  # type: ignore
            source_id=source_id,
        )

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        """Set up streaming handler only for actual streaming responses (SSE)."""
        if not self._enabled:
            return

        match_result: MatchResult | None = flow.metadata.get(OXIMY_METADATA_KEY)
        if not match_result or match_result.classification == "drop":
            return

        # Only set up streaming for actual streaming content types
        if not flow.response:
            return

        content_type = flow.response.headers.get("content-type", "").lower()
        is_streaming = (
            "text/event-stream" in content_type
            or "application/x-ndjson" in content_type
            or "text/plain" in content_type  # Some APIs stream as text/plain
        )

        if not is_streaming:
            logger.debug(
                f"Non-streaming response for {match_result.source_id}: {content_type}"
            )
            return

        # Set up a pipeline context for buffering stream data
        ctx_pipeline = PipelineContext.from_flow(flow)
        self._stream_buffers[flow.id] = ctx_pipeline

        # Create stream handler that collects chunks
        def create_stream_handler(buffer_ctx: PipelineContext):
            def handler(data: bytes) -> bytes:
                # Append to response body for later processing
                if buffer_ctx.response_body is None:
                    buffer_ctx.response_body = data
                else:
                    buffer_ctx.response_body += data
                return data
            return handler

        flow.response.stream = create_stream_handler(ctx_pipeline)
        logger.info(f"Set up streaming buffer for {match_result.source_id}/{match_result.endpoint}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Process responses and write events."""
        if not self._enabled or not self._writer:
            return

        match_result: MatchResult | None = flow.metadata.get(OXIMY_METADATA_KEY)
        if not match_result or match_result.classification == "drop":
            return

        # Check for day reset (clears per-day tracking)
        self._check_day_reset()

        # Apply target filter if set
        target_id = ctx.options.oximy_target_id
        if target_id and match_result.source_id != target_id:
            logger.debug(f"Skipping {match_result.source_id} (target filter: {target_id})")
            return

        try:
            # Handle detection_cache: silently extract context, don't emit event
            if match_result.classification == "detection_cache":
                self._process_detection_cache(flow, match_result)
                return

            event = self._build_event(flow, match_result)
            if event:
                self._writer.write(event)
                self._log_captured_event(event, flow)
        except Exception as e:
            logger.error(f"Failed to process flow: {e}", exc_info=True)
        finally:
            # Clean up buffers
            self._stream_buffers.pop(flow.id, None)

    def _process_detection_cache(self, flow: http.HTTPFlow, match_result: MatchResult) -> None:
        """
        Process a detection source match: extract context and cache it silently.

        No event is emitted - context will be attached to the next feature event.
        """
        tool_id = match_result.source_id or "unknown"
        config = self._get_config_for_match(match_result)
        if not config:
            return

        # Create pipeline context for detection extraction
        pipeline_ctx = PipelineContext.from_flow(flow)

        # Run detection processor to extract and cache context
        # Use config_registry's flattening to handle nested dict format
        detection_sources = self._config_registry._flatten_detection_sources(
            config.get("detection", {})
        )
        if detection_sources:
            detection_processor = get_detection_processor()
            extracted = detection_processor.process(pipeline_ctx, detection_sources, tool_id)
            if extracted:
                logger.debug(f"Cached detection context for {tool_id}: {list(extracted.keys())}")

    def _log_captured_event(self, event: TraceOutput, flow: http.HTTPFlow) -> None:
        """Log a nicely formatted summary of captured AI traffic."""
        # Build client info string
        client_str = ""
        if event.client and event.client.name:
            client_str = f" [{event.client.name}]"
            if (
                event.client.parent_name
                and event.client.parent_name != event.client.name
            ):
                client_str = f" [{event.client.parent_name} > {event.client.name}]"

        # Build model info
        model_str = ""
        if event.interaction and event.interaction.model:
            model_str = f" model={event.interaction.model}"

        # Build timing info
        timing_str = ""
        if event.timing and event.timing.duration_ms:
            timing_str = f" ({event.timing.duration_ms}ms)"

        # Log format: [source_id] METHOD path -> status (timing) [client]
        logger.info(
            f"[{event.source.tool_id}]{client_str} "
            f"{flow.request.method} {flow.request.path[:50]}{'...' if len(flow.request.path) > 50 else ''} "
            f"-> {flow.response.status_code if flow.response else '?'}{model_str}{timing_str}"
        )

    def _build_event(
        self, flow: http.HTTPFlow, match_result: MatchResult
    ) -> TraceOutput | None:
        """Build a TraceOutput from a flow."""
        if not flow.response:
            return None

        # Filter out noisy polling/status endpoints
        path = flow.request.path
        if flow.request.method == "GET" and any(
            x in path for x in ["/stream_status", "/status"]
        ):
            return None

        # Get client process info (captured during request phase)
        client_process: ClientProcess | None = flow.metadata.get(OXIMY_CLIENT_KEY)

        # Calculate timing
        timing = self._calculate_timing(flow)

        # Build transport info
        transport = self._build_transport(flow)

        # Build source info
        source = EventSource(
            type=match_result.source_type if match_result.source_type in ("app", "website") else "website",
            tool_id=match_result.source_id or "unknown",
            feature=match_result.endpoint or "unknown",
        )

        # Build client info
        client_info = None
        if client_process:
            client_info = ClientInfo.from_client_process(client_process)

        # Handle metadata_only classification
        # Only emit ONE metadata_only event per tool per day if no feature events exist
        if match_result.classification == "metadata_only":
            tool_id = match_result.source_id or "unknown"

            # If we've already emitted a feature event for this tool today, skip metadata_only
            if tool_id in self._emitted_feature_tools:
                logger.debug(f"Skipping metadata_only for {tool_id} - feature event already emitted today")
                return None

            # If we've already emitted metadata_only for this tool today, skip
            if tool_id in self._emitted_metadata_tools:
                logger.debug(f"Skipping duplicate metadata_only for {tool_id}")
                return None

            # Mark this tool as having emitted metadata_only today
            self._emitted_metadata_tools.add(tool_id)

            # Consume any cached detection context
            detection_processor = get_detection_processor()
            detection_context = detection_processor.consume_context(tool_id)

            return TraceOutput.create(
                source=source,
                trace_level="metadata_only",
                interaction=Interaction(type="other"),
                transport=transport,
                timing=timing,
                client=client_info,
                context=detection_context if detection_context else None,
                meta={
                    "request_method": flow.request.method,
                    "request_path": flow.request.path,
                    "response_status": flow.response.status_code,
                    "content_length": len(flow.response.content or b""),
                },
            )

        # Get the config for this source
        config = self._get_config_for_match(match_result)
        if not config:
            logger.warning(f"No config found for {match_result.source_id}")
            return None

        # Get the endpoint config
        endpoint_config = self._get_endpoint_config(config, match_result)

        # Create pipeline context
        stream_buffer = self._stream_buffers.get(flow.id)
        if stream_buffer:
            # Use buffered stream data
            pipeline_ctx = stream_buffer
        else:
            # Create fresh context from flow
            pipeline_ctx = PipelineContext.from_flow(flow)

        # Execute pipeline if configured
        if endpoint_config:
            pipeline_ops = endpoint_config.get("pipeline", [])
            if pipeline_ops:
                pipeline = Pipeline(pipeline_ops)
                pipeline_ctx = pipeline.execute(pipeline_ctx)

                if pipeline_ctx.has_error():
                    logger.warning(f"Pipeline error for {match_result.source_id}: {pipeline_ctx.error}")

            # Extract fields if configured
            extract_config = endpoint_config.get("extract", {})
            if extract_config:
                extracted = extract_fields(pipeline_ctx, extract_config)
                pipeline_ctx.merge_extracted(extracted)

        # Get detection context: consume cached context from detection source matches
        # This includes subscription, user info, etc. that was silently cached earlier
        tool_id = match_result.source_id or "unknown"
        detection_processor = get_detection_processor()

        # First consume any cached context from detection_cache matches
        detection_context = detection_processor.consume_context(tool_id)

        # Also try to process detection sources against this current request/response
        # (in case this endpoint also matches a detection source)
        # Use config_registry's flattening to handle nested dict format
        detection_sources = self._config_registry._flatten_detection_sources(
            config.get("detection", {})
        )
        if detection_sources:
            additional_context = detection_processor.process(
                pipeline_ctx, detection_sources, tool_id
            )
            if additional_context:
                # Merge additional context into existing
                if detection_context:
                    self._deep_merge(detection_context, additional_context)
                else:
                    detection_context = additional_context

        # Mark this tool as having emitted a feature event today
        # This prevents metadata_only events from being emitted for this tool
        self._emitted_feature_tools.add(tool_id)

        # Determine trace_level based on endpoint role and output mode
        # - "detect" role or mode indicates metadata/activity detection without full content
        # - Default to "full_extraction" for normal endpoints
        trace_level = "full_extraction"
        if endpoint_config:
            endpoint_role = endpoint_config.get("role", "both")
            output_config = endpoint_config.get("output", {})
            output_mode = output_config.get("mode", "extract")

            # If endpoint is detection-only, use feature_extraction level
            if endpoint_role == "detect" or output_mode == "detect":
                trace_level = "feature_extraction"

        # Build interaction from pipeline context
        interaction = self._build_interaction(pipeline_ctx, match_result, endpoint_config)

        # Get output config
        output_config = endpoint_config.get("output", {}) if endpoint_config else {}

        # Build usage if available
        usage = None
        if pipeline_ctx.extracted.get("usage"):
            usage_data = pipeline_ctx.extracted["usage"]
            usage = Usage(
                input_tokens=usage_data.get("input_tokens"),
                output_tokens=usage_data.get("output_tokens"),
                total_tokens=usage_data.get("total_tokens"),
            )

        # Build raw data if requested
        raw_data = None
        include_raw = output_config.get("include_raw", ctx.options.oximy_include_raw)
        if include_raw:
            raw_data = {}
            if pipeline_ctx.request_data:
                raw_data["request"] = pipeline_ctx.request_data

            # For response, use fallback chain to ensure we always have an object:
            # 1. accumulated (clean extracted data from streaming)
            # 2. response_data if it's a dict (non-streaming)
            # 3. wrap list in {"_chunks": [...]} (fallback for streaming if accumulate failed)
            if pipeline_ctx.accumulated:
                raw_data["response"] = pipeline_ctx.accumulated
            elif isinstance(pipeline_ctx.response_data, dict):
                raw_data["response"] = pipeline_ctx.response_data
            elif isinstance(pipeline_ctx.response_data, list):
                # Wrap chunks in object to satisfy schema, preserve all data
                raw_data["response"] = {"_chunks": pipeline_ctx.response_data}

        return TraceOutput.create(
            source=source,
            trace_level=trace_level,  # type: ignore
            interaction=interaction,
            transport=transport,
            timing=timing,
            client=client_info,
            usage=usage,
            context=detection_context,
            raw=raw_data,
        )

    def _build_transport(self, flow: http.HTTPFlow) -> Transport:
        """Build Transport info from flow."""
        url = flow.request.pretty_url
        protocol: str | None = None
        if url.startswith("https://"):
            protocol = "https"
        elif url.startswith("http://"):
            protocol = "http"
        elif url.startswith("wss://"):
            protocol = "wss"
        elif url.startswith("ws://"):
            protocol = "ws"

        content_type = None
        if flow.response:
            content_type = flow.response.headers.get("content-type")

        referer = flow.request.headers.get("referer") or flow.request.headers.get("referrer")
        origin = flow.request.headers.get("origin")

        return Transport(
            protocol=protocol,  # type: ignore
            method=flow.request.method,
            url=url,
            status_code=flow.response.status_code if flow.response else None,
            content_type=content_type,
            referer=referer,
            origin=origin,
        )

    def _build_interaction(
        self,
        ctx: PipelineContext,
        match_result: MatchResult,
        endpoint_config: dict | None,
    ) -> Interaction:
        """Build Interaction from pipeline context."""
        # Determine interaction type from feature type
        feature_type = match_result.feature_type or "other"
        if feature_type not in ("chat", "codegen", "asset_creation", "text_manipulation", "platform_output", "other"):
            feature_type = "other"

        # Helper to get extracted value with fallback keys
        def get_extracted(*keys: str) -> str | None:
            for key in keys:
                val = ctx.extracted.get(key)
                if val is not None:
                    return val if isinstance(val, str) else str(val)
            return None

        # Build input - look for request.prompt, prompt, input
        input_data = None
        prompt = get_extracted("request.prompt", "prompt", "input")
        if prompt:
            input_data = InteractionInput(text=prompt)

        # Build output - look for response.content, content, response
        # Also check accumulated for streaming responses
        output_data = None
        content = get_extracted("response.content", "content", "response") or ctx.accumulated.get("content")
        thinking = get_extracted("response.thinking", "thinking") or ctx.accumulated.get("thinking")
        if content or thinking:
            output_data = InteractionOutput(
                text=content if isinstance(content, str) else None,
                thinking=thinking if isinstance(thinking, str) else None,
            )

        # Get model - check both request and response model
        model = get_extracted("response.model", "request.model", "model") or ctx.accumulated.get("model")

        # Get conversation/message IDs - check prefixed and unprefixed
        conversation_id = get_extracted("response.conversation_id", "request.conversation_id", "conversation_id")
        message_id = get_extracted("response.message_id", "request.message_id", "message_id")

        return Interaction(
            type=feature_type,  # type: ignore
            input=input_data,
            output=output_data,
            model=model,
            conversation_id=conversation_id,
            message_id=message_id,
        )

    def _get_config_for_match(self, match_result: MatchResult) -> dict | None:
        """Get the config dict for a match result."""
        if not self._config_registry:
            return None

        return self._config_registry.get_config(match_result.source_id or "")

    def _get_endpoint_config(self, config: dict, match_result: MatchResult) -> dict | None:
        """Get the endpoint configuration for a feature."""
        if not match_result.feature_key:
            return None

        features = config.get("features", {})
        feature = features.get(match_result.feature_key, {})
        endpoints = feature.get("endpoints", [])

        # Return first endpoint (usually there's only one)
        return endpoints[0] if endpoints else None

    def _calculate_timing(self, flow: http.HTTPFlow) -> EventTiming:
        """Calculate timing metrics from flow timestamps."""
        duration_ms = None
        ttfb_ms = None
        started_at = None

        if flow.request.timestamp_start:
            from datetime import datetime, timezone
            started_at = datetime.fromtimestamp(
                flow.request.timestamp_start, tz=timezone.utc
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z")

            if flow.response:
                if flow.response.timestamp_end:
                    duration_ms = int(
                        (flow.response.timestamp_end - flow.request.timestamp_start) * 1000
                    )
                if flow.response.timestamp_start:
                    ttfb_ms = int(
                        (flow.response.timestamp_start - flow.request.timestamp_start)
                        * 1000
                    )

        return EventTiming(started_at=started_at, duration_ms=duration_ms, ttfb_ms=ttfb_ms)

    # -------------------------------------------------------------------------
    # TLS Hooks - Handle certificate pinning passthrough
    # -------------------------------------------------------------------------

    def tls_clienthello(self, data) -> None:
        """Check if host should bypass TLS interception."""
        if self._enabled and self._tls_passthrough:
            self._tls_passthrough.tls_clienthello(data)

    def tls_failed_client(self, data) -> None:
        """Record TLS failures to learn certificate-pinned hosts."""
        if self._enabled and self._tls_passthrough:
            self._tls_passthrough.tls_failed_client(data)

    def done(self) -> None:
        """Clean up on shutdown."""
        self._cleanup()

    def _cleanup(self) -> None:
        """Clean up resources."""
        # Disable system proxy (development convenience)
        _set_system_proxy(enable=False)

        if self._writer:
            self._writer.close()
            self._writer = None

        if self._process_resolver:
            self._process_resolver.clear_cache()
            self._process_resolver = None

        self._tls_passthrough = None
        self._stream_buffers.clear()
        self._config_registry = None
        self._bundle = None


# For use with `mitmdump -s .../oximy/addon.py`
addons = [OximyAddon()]
