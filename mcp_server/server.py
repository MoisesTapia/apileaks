"""
mcp_server.server — APILeakMCPServer: main server class.

This module provides :class:`APILeakMCPServer`, the entry point that wires
together the :class:`~mcp_server.tool_registry.MCPToolRegistry`, the
:class:`~mcp_server.confirmation_gate.DestructiveConfirmationGate`, and the
chosen transport (stdio / HTTP).

Task 3.1 adds a working ``stdio`` transport: the :meth:`APILeakMCPServer.serve`
method builds an MCP :class:`mcp.server.Server` instance, registers
``list_tools`` / ``call_tool`` handlers that delegate to the
:class:`~mcp_server.tool_registry.MCPToolRegistry`, and then drives the
``stdio_server()`` read/write loop (Requirement 2.1).

Task 3.2 adds the HTTP/SSE transport:

* Uses :class:`mcp.server.sse.SseServerTransport` with Starlette + uvicorn
  for SSE streaming as per the MCP specification (Requirement 2.2).
* Enforces Bearer token authentication before accepting connections
  (Requirement 2.3).  The server refuses to start in HTTP mode without an
  auth token configured.
* When ``--tls-cert`` / ``--tls-key`` are provided, uvicorn is started with
  TLS; plain HTTP clients receive an SSL handshake error (Requirement 2.5).
* When no certificates are provided, a prominent WARNING is logged directing
  the operator to place the server behind a TLS-terminating reverse proxy
  (nginx, Caddy, Traefik, etc.) — see ``DEPLOYMENT.md`` (Requirement 2.5).

TLS deployment guide
--------------------
If you do not supply ``--tls-cert`` / ``--tls-key``, you MUST deploy this
server behind a TLS-terminating reverse proxy.  Example (nginx)::

    server {
        listen 443 ssl;
        ssl_certificate     /etc/ssl/certs/apileak.crt;
        ssl_certificate_key /etc/ssl/private/apileak.key;
        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host $host;
        }
    }

Never expose the plain-HTTP port directly to untrusted networks.
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys
from typing import Any

import mcp.types as mcp_types
from mcp.server import Server as MCPSDKServer
from mcp.server.stdio import stdio_server
from starlette.types import Receive, Scope, Send

from core.logging import get_logger
from mcp_server.audit_log import MCPAuditLogger
from mcp_server.confirmation_gate import DestructiveConfirmationGate
from mcp_server.rate_limiter import MCPRateLimiter
from mcp_server.schemas import MCPServerConfig, MCPToolError, MCPToolSpec
from mcp_server.tool_registry import MCPToolRegistry

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Bearer-token ASGI middleware (Requirement 2.3)
# ---------------------------------------------------------------------------

_UNAUTHORIZED_BODY = json.dumps(
    {
        "error": "Unauthorized",
        "message": (
            "A valid Bearer token is required.  "
            "Provide the 'Authorization: Bearer <token>' HTTP header."
        ),
    },
    ensure_ascii=False,
).encode()

_UNAUTHORIZED_HEADERS = [
    (b"content-type", b"application/json"),
    (b"www-authenticate", b'Bearer realm="APILeak MCP Server"'),
    (b"content-length", str(len(_UNAUTHORIZED_BODY)).encode()),
]


class _BearerAuthMiddleware:
    """Lightweight ASGI middleware that enforces a static Bearer token.

    Rejects any HTTP/WebSocket connection that does not present the correct
    ``Authorization: Bearer <token>`` header with an HTTP 401 response.

    This satisfies Requirement 2.3 without pulling in a full OAuth2 stack —
    a single shared token is sufficient for the local/VPN deployment model
    APILeak targets.
    """

    def __init__(self, app: Any, token: str) -> None:
        self._app = app
        self._token = token

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket"):
            headers: dict[bytes, bytes] = dict(scope.get("headers", []))
            raw_auth = headers.get(b"authorization", b"")
            auth_value = raw_auth.decode("latin-1", errors="replace")
            # Case-insensitive "bearer " prefix check
            if not auth_value.lower().startswith("bearer "):
                await self._send_401(send)
                return
            provided_token = auth_value[7:].strip()
            if provided_token != self._token:
                await self._send_401(send)
                return
        await self._app(scope, receive, send)

    @staticmethod
    async def _send_401(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": _UNAUTHORIZED_HEADERS,
            }
        )
        await send({"type": "http.response.body", "body": _UNAUTHORIZED_BODY})


class APILeakMCPServer:
    """MCP server that exposes APILeak capabilities as invocable tools.

    Lifecycle::

        config = MCPServerConfig(transport="stdio")
        server = APILeakMCPServer(transport="stdio", config=config)
        await server.serve()   # blocks until shutdown signal

    The server is the single public entry point for the MCP layer.  Transport
    selection (stdio vs HTTP), TLS enforcement, rate limiting, and the audit
    log are all configured via :class:`~mcp_server.schemas.MCPServerConfig`.
    """

    def __init__(self, transport: str, config: MCPServerConfig) -> None:
        """Initialise the server.

        Args:
            transport: Transport type — ``"stdio"`` or ``"http"``.
            config: Server configuration including security settings.
        """
        self.transport = transport
        self.config = config
        self.confirmation_gate = DestructiveConfirmationGate(
            allow_destructive=config.allow_destructive
        )
        # Build the rate limiter from config (Requirement 15.2, 15.3).
        self.rate_limiter = MCPRateLimiter(
            rate_limit_per_minute=config.rate_limit_per_minute,
        )
        # Build the audit logger when a path is configured (Requirement 12.4).
        self._audit_logger: MCPAuditLogger | None = None
        if config.audit_log_path:
            from pathlib import Path as _Path
            self._audit_logger = MCPAuditLogger(_Path(config.audit_log_path))

        self.registry = MCPToolRegistry(
            confirmation_gate=self.confirmation_gate,
            rate_limiter=self.rate_limiter,
            audit_logger=self._audit_logger,
        )
        self._tool_manifest_hash: str | None = None

        # Graceful-shutdown state (Requirement 2.4)
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._active_tasks: set[asyncio.Task[Any]] = set()
        self._uv_server: Any | None = None  # set in _serve_http(); type: uvicorn.Server

        self._register_default_tools()
        self._log_startup_info()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def serve(self) -> None:
        """Start the server loop on the configured transport.

        Supports ``"stdio"`` (Requirement 2.1, Task 3.1) and ``"http"``
        (Requirement 2.2, Task 3.2) transports.

        Installs OS signal handlers for SIGINT/SIGTERM so that a termination
        signal triggers :meth:`shutdown` cleanly (Requirement 2.4).

        This method blocks until the transport closes (e.g. when the MCP
        client disconnects, EOF on stdio, or the HTTP server receives SIGINT).
        """
        self._install_signal_handlers()
        if self.transport == "stdio":
            await self._serve_stdio()
        elif self.transport == "http":
            await self._serve_http()
        else:
            raise NotImplementedError(
                f"Transport '{self.transport}' is not supported. "
                "Use '--transport stdio' or '--transport http'."
            )

    # ------------------------------------------------------------------
    # Graceful shutdown (Requirement 2.4)
    # ------------------------------------------------------------------

    async def shutdown(self) -> None:
        """Trigger a graceful shutdown of the server.

        * Sets the internal shutdown event/flag.
        * Logs ``"mcp_server_shutdown_requested"``.
        * Cancels every in-flight tool-invocation :class:`asyncio.Task`
          currently tracked in :attr:`_active_tasks`.
        * For HTTP transport: signals uvicorn to stop by setting
          ``server.should_exit = True``.

        This method is idempotent — repeated calls are safe.

        Requirement 2.4
        """
        if self._shutdown_event.is_set():
            return  # already shutting down — ignore duplicate calls

        logger.info("mcp_server_shutdown_requested", transport=self.transport)
        self._shutdown_event.set()

        # Cancel all in-progress tool invocation tasks.
        tasks_to_cancel = list(self._active_tasks)
        for task in tasks_to_cancel:
            if not task.done():
                task.cancel()

        if tasks_to_cancel:
            # Wait for cancellations to propagate without re-raising.
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        # Signal uvicorn to stop accepting new connections and drain existing ones.
        if self._uv_server is not None:
            self._uv_server.should_exit = True

        logger.info(
            "mcp_server_shutdown_complete",
            cancelled_tasks=len(tasks_to_cancel),
        )

    def _install_signal_handlers(self) -> None:
        """Register OS signal handlers that trigger :meth:`shutdown`.

        Uses the asyncio event-loop's ``add_signal_handler`` on POSIX platforms
        (Linux/macOS) for async-safe delivery.  On Windows, falls back to
        ``signal.signal()`` with ``loop.call_soon_threadsafe`` so the shutdown
        coroutine is scheduled on the correct event loop thread.

        All registrations are wrapped in try/except so failures (e.g. running
        inside a thread where signal handling is not permitted) are logged as
        warnings rather than crashing the server.

        Requirement 2.4
        """
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            logger.warning("mcp_server_signal_handler_skipped — no running event loop")
            return

        def _schedule_shutdown() -> None:
            """Schedule shutdown() on the event loop from a signal context."""
            loop.create_task(self.shutdown())

        if sys.platform != "win32":
            # POSIX: add_signal_handler is the async-safe approach.
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, _schedule_shutdown)
                except (OSError, NotImplementedError, ValueError) as exc:
                    logger.warning(
                        "mcp_server_signal_handler_failed",
                        signal=sig.name,
                        reason=str(exc),
                    )
        else:
            # Windows: add_signal_handler is not implemented.  Use signal.signal()
            # and marshal back to the event loop thread.
            def _windows_handler(signum: int, frame: Any) -> None:  # noqa: ARG001
                loop.call_soon_threadsafe(_schedule_shutdown)

            for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
                sig_obj = getattr(signal, sig_name, None)
                if sig_obj is None:
                    continue
                try:
                    signal.signal(sig_obj, _windows_handler)
                except (OSError, ValueError) as exc:
                    logger.warning(
                        "mcp_server_signal_handler_failed",
                        signal=sig_name,
                        reason=str(exc),
                    )

    # ------------------------------------------------------------------
    # Stdio transport (Requirement 2.1)
    # ------------------------------------------------------------------

    async def _serve_stdio(self) -> None:
        """Drive the MCP protocol over stdin/stdout (Requirement 2.1).

        Builds an :class:`mcp.server.Server` instance, wires up
        ``list_tools`` and ``call_tool`` handlers that delegate to
        :attr:`registry`, and then runs the stdio read/write loop provided
        by the MCP Python SDK.
        """
        sdk_server = self._build_mcp_sdk_server()
        init_options = sdk_server.create_initialization_options()

        logger.info("mcp_server_stdio_starting")
        async with stdio_server() as (read_stream, write_stream):
            await sdk_server.run(read_stream, write_stream, init_options)
        logger.info("mcp_server_stdio_stopped")

    # ------------------------------------------------------------------
    # HTTP/SSE transport (Requirement 2.2, 2.3, 2.5)
    # ------------------------------------------------------------------

    async def _serve_http(self) -> None:
        """Drive the MCP protocol over HTTP with SSE streaming (Requirement 2.2).

        Builds a Starlette ASGI application backed by
        :class:`mcp.server.sse.SseServerTransport`, wraps it with
        :class:`_BearerAuthMiddleware` when an auth token is configured
        (Requirement 2.3), and runs it via uvicorn.

        TLS behaviour (Requirement 2.5):

        * If ``config.tls_cert`` *and* ``config.tls_key`` are set, uvicorn is
          launched with SSL.  Any plain-HTTP client will receive a TLS
          handshake error from the server before our application code runs.
        * If no certificate is provided, the server starts in plain-HTTP mode
          and a prominent WARNING is logged reminding the operator to place the
          server behind a TLS-terminating reverse proxy.

        Raises:
            ValueError: If HTTP transport is requested without an auth token
                configured (Requirement 2.3).
        """
        import uvicorn

        if not self.config.auth_token:
            raise ValueError(
                "HTTP transport requires an authentication token.  "
                "Set --mcp-auth-token or the APILEAKS_MCP_AUTH_TOKEN environment "
                "variable before starting the HTTP MCP server (Requirement 2.3)."
            )

        port = self.config.port or 8080
        ssl_certfile = self.config.tls_cert
        ssl_keyfile = self.config.tls_key
        tls_enabled = bool(ssl_certfile and ssl_keyfile)

        if tls_enabled:
            logger.info(
                "mcp_server_http_tls_enabled",
                port=port,
                tls_cert=ssl_certfile,
            )
        else:
            logger.warning(
                "mcp_server_http_no_tls — no TLS certificate configured. "
                "The HTTP MCP server is running in plain-HTTP mode. "
                "You MUST deploy this server behind a TLS-terminating reverse proxy "
                "(nginx, Caddy, Traefik, etc.) before exposing it to any untrusted network. "
                "See DEPLOYMENT.md for a reference configuration. "
                "(Requirement 2.5 / OWASP MCP07)",
                port=port,
            )

        app = self._build_starlette_app()

        # When TLS cert/key are provided, pass them to uvicorn so it runs in
        # HTTPS mode.  Plain-HTTP clients will receive a TLS handshake error
        # before our application code is reached (Requirement 2.5).
        uv_config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=port,
            ssl_certfile=ssl_certfile if tls_enabled else None,
            ssl_keyfile=ssl_keyfile if tls_enabled else None,
            log_level="warning",  # Silence uvicorn's own banners; we log our own.
            access_log=False,
        )
        uv_server = uvicorn.Server(uv_config)

        logger.info(
            "mcp_server_http_starting",
            port=port,
            tls=tls_enabled,
        )
        self._uv_server = uv_server
        await uv_server.serve()
        self._uv_server = None
        logger.info("mcp_server_http_stopped")

    def _build_starlette_app(self) -> Any:
        """Build and return the Starlette ASGI application for HTTP/SSE transport.

        The returned app exposes two routes:

        * ``GET /sse`` — establishes an SSE stream for server→client messages.
        * ``POST /messages/`` — receives client→server MCP protocol messages.

        When ``config.auth_token`` is set, the whole app is wrapped with
        :class:`_BearerAuthMiddleware` so every request must present the
        correct ``Authorization: Bearer <token>`` header (Requirement 2.3).

        This method is intentionally separate from :meth:`_serve_http` so
        that tests can build the ASGI app in-process and drive it via
        :class:`httpx.AsyncClient` without starting a real uvicorn server.
        """
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import Response
        from starlette.routing import Mount, Route

        sdk_server = self._build_mcp_sdk_server()
        sse_transport = SseServerTransport("/messages/")

        async def handle_sse(request: Request) -> Response:
            async with sse_transport.connect_sse(
                request.scope, request.receive, request._send
            ) as streams:
                await sdk_server.run(
                    streams[0],
                    streams[1],
                    sdk_server.create_initialization_options(),
                )
            return Response()

        routes = [
            Route("/sse", endpoint=handle_sse, methods=["GET"]),
            Mount("/messages/", app=sse_transport.handle_post_message),
        ]

        starlette_app: Any = Starlette(routes=routes)

        # Wrap with Bearer auth middleware when a token is configured
        # (Requirement 2.3).
        if self.config.auth_token:
            starlette_app = _BearerAuthMiddleware(starlette_app, self.config.auth_token)

        return starlette_app

    def _build_mcp_sdk_server(self) -> MCPSDKServer:
        """Build and return a configured MCP SDK :class:`~mcp.server.Server`.

        Registers two handlers on the SDK server:

        * ``list_tools`` — returns all :class:`~mcp_server.schemas.MCPToolSpec`
          objects from the registry as :class:`mcp.types.Tool` descriptors.
        * ``call_tool`` — dispatches to :meth:`MCPToolRegistry.invoke` and
          converts the result / exception to the MCP protocol format.

        This helper is intentionally public (package-private via underscore
        convention) so that tests can build the SDK server in-process without
        starting a real transport.
        """
        registry = self.registry
        sdk_server = MCPSDKServer(name="apileak-mcp-server", version="0.1.0")

        @sdk_server.list_tools()
        async def handle_list_tools() -> list[mcp_types.Tool]:
            return [
                mcp_types.Tool(
                    name=spec.name,
                    description=spec.description,
                    inputSchema=spec.input_schema,
                )
                for spec in registry.list_tools()
            ]

        @sdk_server.call_tool()
        async def handle_call_tool(
            name: str, arguments: dict[str, Any] | None
        ) -> list[mcp_types.ContentBlock]:
            params: dict[str, Any] = arguments or {}
            try:
                result = await registry.invoke(name, params, confirmation=None)
            except MCPToolError as exc:
                # Surface structured MCP errors as a text block so the client
                # receives a machine-readable description without raw tracebacks
                # (Requirement 1.5).
                error_payload = json.dumps(
                    {"error_code": exc.error_code, "message": exc.message},
                    ensure_ascii=False,
                )
                return [mcp_types.TextContent(type="text", text=error_payload)]

            # Build a text block with a JSON-serialisable summary.
            output: dict[str, Any] = {
                "tool_name": result.tool_name,
                "finding_count": len(result.findings),
                "untrusted_content": result.untrusted_content,
                "metadata": result.metadata,
            }
            if result.raw_output:
                output["summary"] = result.raw_output

            return [mcp_types.TextContent(type="text", text=json.dumps(output, ensure_ascii=False))]

        return sdk_server

    # ------------------------------------------------------------------
    # Internal setup
    # ------------------------------------------------------------------

    def _register_default_tools(self) -> None:
        """Register one MCP tool per existing CLI command.

        Task 2.1: ``apileak.scan`` is registered here.
        Task 2.2: ``apileak.owasp.*`` tools are registered here (one per module).
        Task 2.3: ``apileak.jwt.attack_test`` and ``apileak.discovery.*`` tools
                  are registered here.
        Task 2.4: ``apileak.cloud_audit`` is registered here as a documented
                  stub; the handler raises ``NOT_IMPLEMENTED`` until the
                  ``cloud-gateway-security-audit`` spec is complete (see
                  ``mcp_server/cloud_audit_tool.py`` for details).
        """
        from mcp_server.cloud_audit_tool import build_cloud_audit_tool_spec
        from mcp_server.discovery_tools import build_discovery_tool_specs
        from mcp_server.jwt_tools import build_jwt_tool_specs
        from mcp_server.owasp_tools import build_owasp_tool_specs
        from mcp_server.scan_handler import build_scan_tool_spec

        self.registry.register(build_scan_tool_spec())
        logger.debug("mcp_tool_registered", tool_name="apileak.scan")

        for spec in build_owasp_tool_specs():
            self.registry.register(spec)
            logger.debug("mcp_tool_registered", tool_name=spec.name)

        for spec in build_jwt_tool_specs():
            self.registry.register(spec)
            logger.debug("mcp_tool_registered", tool_name=spec.name)

        for spec in build_discovery_tool_specs():
            self.registry.register(spec)
            logger.debug("mcp_tool_registered", tool_name=spec.name)

        self.registry.register(build_cloud_audit_tool_spec())
        logger.debug("mcp_tool_registered", tool_name="apileak.cloud_audit")

    def _log_startup_info(self) -> None:
        """Log startup diagnostics required by the spec.

        - Active security mode (Requirement 4.3).
        - Tool manifest hash (Requirement 4.7 / OWASP MCP03).
        - Active rate-limit and default timeout (Requirement 15.3).
        """
        self._tool_manifest_hash = self.registry.manifest_hash()

        # Derive the default max_execution_seconds from MCPToolSpec's default so
        # the logged value always matches the actual default (Requirement 15.3).
        import dataclasses as _dc
        _spec_defaults = {f.name: f.default for f in _dc.fields(MCPToolSpec)}
        default_max_execution_seconds = _spec_defaults.get("max_execution_seconds", 300.0)

        logger.info(
            "mcp_server_starting",
            transport=self.transport,
            allow_destructive=self.config.allow_destructive,
            security_mode="destructive_enabled" if self.config.allow_destructive else "safe_default",
            tool_manifest_hash=self._tool_manifest_hash,
            rate_limit_per_minute=self.config.rate_limit_per_minute,
            default_max_execution_seconds=default_max_execution_seconds,
        )

        # Write the startup sentinel to the audit log (Requirement 12.4).
        if self._audit_logger is not None:
            self._audit_logger.record_startup(self._tool_manifest_hash)
