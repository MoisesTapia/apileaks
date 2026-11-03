# Deployment Guide — APILeak MCP Server (HTTP Transport)

## TLS Requirements (Requirement 2.5 / OWASP MCP07)

When running `apileaks mcp-server --transport http`, the server **MUST** be
protected by TLS.  Exposing MCP tools over plain HTTP allows any network
observer to read and replay Bearer tokens and scan results.

You have two options:

---

### Option A — Provide TLS certificates directly

Pass your certificate and private key to the server.  The server will load
them and accept only HTTPS connections; plain-HTTP clients receive a TLS
handshake error:

```bash
apileaks mcp-server \
  --transport http \
  --port 8443 \
  --mcp-auth-token "$MCP_TOKEN" \
  --tls-cert /etc/ssl/certs/apileak.crt \
  --tls-key  /etc/ssl/private/apileak.key
```

The server logs `mcp_server_http_tls_enabled` at startup when TLS is active.

---

### Option B — Deploy behind a TLS-terminating reverse proxy (recommended)

If you do not have certificates handy, keep the server on a loopback address
and let your reverse proxy handle TLS termination.  The server logs a
prominent **WARNING** (`mcp_server_http_no_tls`) if it starts without
certificates, reminding you that a reverse proxy is required.

#### nginx example

```nginx
server {
    listen 443 ssl;
    server_name mcp.example.internal;

    ssl_certificate     /etc/ssl/certs/apileak.crt;
    ssl_certificate_key /etc/ssl/private/apileak.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Forward all traffic to the local MCP server
    location / {
        proxy_pass       http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE requires long-lived connections and chunked transfer
        proxy_buffering           off;
        proxy_cache               off;
        proxy_read_timeout        3600s;
        chunked_transfer_encoding on;
    }
}

# Reject plain-HTTP connections with an explanatory error
server {
    listen 80;
    server_name mcp.example.internal;
    return 444 "TLS required. Connect to port 443.";
}
```

#### Caddy example

```caddy
mcp.example.internal {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy automatically provisions and renews TLS certificates via Let's Encrypt.

---

## Authentication (Requirement 2.3)

HTTP transport **always** requires a Bearer token.  Every request must include:

```
Authorization: Bearer <your-token>
```

Requests without a valid token receive an HTTP 401 response.

Set the token via the CLI flag or the environment variable:

```bash
export APILEAKS_MCP_AUTH_TOKEN="$(openssl rand -hex 32)"
apileaks mcp-server --transport http --port 8080
```

Never commit the token to source control.  Use environment variables, a
secrets manager, or a vault.

---

## stdio Transport Trust Model (Requirement 2.6)

The `--transport stdio` mode implies that the process launching the MCP
server is already trusted (it runs as the same OS user).  Only use `stdio`
transport when the MCP client (Claude Desktop, Kiro, etc.) is running locally
by the same user.  Do not expose the stdio transport over a network socket.
