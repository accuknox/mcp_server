# Implementation Plan - HTTPS Support for FastMCP Server

The goal is to enable HTTPS support for the `fastmcp_server.py` to ensure secure communication.

## User Review Required

> [!IMPORTANT]
> This change requires valid SSL certificates (`cert.pem` and `key.pem`).
> For testing, we will generate self-signed certificates.
> In production, valid certificates should be provided.

## Proposed Changes

### [Server Configuration]

#### [MODIFY] [fastmcp_server.py](file:///home/satyam/accuknox/mcp_server/fastmcp_server.py)
- Update `mcp.run` to accept and pass SSL configuration arguments.
- Use environment variables `SSL_CERT_FILE` and `SSL_KEY_FILE` to specify certificate paths.
- If these env vars are set, pass `ssl_certfile` and `ssl_keyfile` to `mcp.run`.

## Verification Plan

### Automated Tests
1.  Generate self-signed certificates:
    ```bash
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
    ```
2.  Run the server with SSL enabled:
    ```bash
    export SSL_CERT_FILE=$(pwd)/cert.pem
    export SSL_KEY_FILE=$(pwd)/key.pem
    python3 fastmcp_server.py
    ```
3.  Verify connection using `curl`:
    ```bash
    curl -k https://localhost:8000/health
    ```
    Expected output: `{"status": "healthy"}`

### Manual Verification
- Verify that the server starts without errors when SSL certs are provided.
- Verify that the server falls back to HTTP (or fails gracefully/warns) if certs are missing but expected (optional, but good practice).
