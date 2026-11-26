#!/usr/bin/env python3
"""Verify direct Power LLM Wiki OAuth, deny paths, tools, and rollback."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid


TEST_PAGE = "operations/power-wiki-write-check-20261008.md"


def required_env(name: str, default: str | None = None) -> str:
    """Return one required environment value."""
    value = os.environ.get(name, default or "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is empty: {name}")
    return value


def read_secret(path: Path) -> str:
    """Read one nonempty secret without logging it."""
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"Required secret file is empty: {path}")
    return value


class HttpError(RuntimeError):
    """Represent an HTTP failure without retaining its response body."""

    def __init__(self, status: int, operation: str):
        """Initialize the error."""
        super().__init__(f"{operation} failed with HTTP {status}")
        self.status = status


def http_json(
    method: str,
    url: str,
    data: Any = None,
    *,
    token: str | None = None,
    form: bool = False,
) -> Any:
    """Send one JSON or form request."""
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        if form:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(data).encode("utf-8")
        else:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")
    request = urllib.request.Request(url, method=method, headers=headers, data=body)
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        exc.read(4096)
        raise HttpError(exc.code, f"{method} {urllib.parse.urlparse(url).path}") from exc


def jwt_claims(token: str) -> dict[str, Any]:
    """Decode unverified claims for assertions after the issuer signs the token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("Access token is not a JWT")
    encoded = parts[1] + "=" * (-len(parts[1]) % 4)
    value = json.loads(base64.urlsafe_b64decode(encoded))
    if not isinstance(value, dict):
        raise RuntimeError("Access token claims are not an object")
    return value


def jwt_header(token: str) -> dict[str, Any]:
    """Decode the non-secret JWT protected header for diagnostics."""
    encoded = token.split(".", maxsplit=1)[0]
    encoded += "=" * (-len(encoded) % 4)
    value = json.loads(base64.urlsafe_b64decode(encoded))
    return value if isinstance(value, dict) else {}


class KeycloakAdmin:
    """Manage isolated Keycloak verification objects."""

    def __init__(self, base_url: str, realm: str, username: str, password: str):
        """Authenticate to the Keycloak administration API."""
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        response = http_json(
            "POST",
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            {
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": username,
                "password": password,
            },
            form=True,
        )
        self.token = str(response["access_token"])

    def request(self, method: str, path: str, data: Any = None) -> Any:
        """Send one realm administration request."""
        realm = urllib.parse.quote(self.realm)
        return http_json(method, f"{self.base_url}/admin/realms/{realm}{path}", data, token=self.token)

    def client(self, client_id: str) -> dict[str, Any] | None:
        """Return one client by clientId."""
        query = urllib.parse.urlencode({"clientId": client_id})
        clients = self.request("GET", f"/clients?{query}")
        return next((item for item in clients if item.get("clientId") == client_id), None)

    def create_client(self, client_id: str, secret: str, audience: str) -> str:
        """Create a direct-grant client with one explicit audience mapper."""
        existing = self.client(client_id)
        if existing:
            self.request("DELETE", f"/clients/{urllib.parse.quote(str(existing['id']))}")
        self.request(
            "POST",
            "/clients",
            {
                "clientId": client_id,
                "name": "Temporary direct Power Wiki verifier",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": secret,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": False,
                # DCR clients use Keycloak's full-scope default. Mirror that
                # behavior so the assigned realm role is present in the token.
                "fullScopeAllowed": True,
            },
        )
        created = self.client(client_id)
        if not created:
            raise RuntimeError("Keycloak did not create the direct verification client")
        internal_id = str(created["id"])
        self.request(
            "POST",
            f"/clients/{urllib.parse.quote(internal_id)}/protocol-mappers/models",
            {
                "name": "Verification resource audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.client.audience": audience,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            },
        )
        scopes = self.request("GET", "/client-scopes")
        mcp_scope = next((item for item in scopes if item.get("name") == "mcp:tools"), None)
        if not mcp_scope:
            raise RuntimeError("Keycloak mcp:tools client scope is missing")
        self.request(
            "PUT",
            f"/clients/{urllib.parse.quote(internal_id)}/optional-client-scopes/{urllib.parse.quote(str(mcp_scope['id']))}",
        )
        return internal_id

    def create_user(self, email: str, password: str) -> str:
        """Create one complete temporary user."""
        query = urllib.parse.urlencode({"username": email, "exact": "true"})
        for user in self.request("GET", f"/users?{query}"):
            self.request("DELETE", f"/users/{urllib.parse.quote(str(user['id']))}")
        self.request(
            "POST",
            "/users",
            {
                "username": email,
                "email": email,
                "firstName": "Power Wiki",
                "lastName": "Verifier",
                "enabled": True,
                "emailVerified": True,
                "requiredActions": [],
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
        users = self.request("GET", f"/users?{query}")
        if not users:
            raise RuntimeError("Keycloak did not create a direct verification user")
        return str(users[0]["id"])

    def assign_realm_role(self, user_id: str, role_name: str) -> None:
        """Assign one existing realm role to one user."""
        role = self.request("GET", f"/roles/{urllib.parse.quote(role_name, safe='')}")
        self.request(
            "POST",
            f"/users/{urllib.parse.quote(user_id)}/role-mappings/realm",
            [{"id": role["id"], "name": role["name"]}],
        )

    def password_token(
        self,
        client_id: str,
        client_secret: str,
        email: str,
        password: str,
        scope: str,
    ) -> str:
        """Get a user access token for a negative or positive path."""
        response = http_json(
            "POST",
            f"{self.base_url}/realms/{urllib.parse.quote(self.realm)}/protocol/openid-connect/token",
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "password",
                "username": email,
                "password": password,
                "scope": scope,
            },
            form=True,
        )
        return str(response["access_token"])


def parse_mcp_response(raw: bytes, content_type: str) -> dict[str, Any] | None:
    """Parse one JSON or SSE MCP response."""
    if not raw:
        return None
    text = raw.decode("utf-8")
    if "text/event-stream" in content_type:
        events = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        if not events:
            raise RuntimeError("MCP SSE response contained no data event")
        text = events[-1]
    value = json.loads(text)
    if not isinstance(value, dict):
        raise RuntimeError("MCP response was not a JSON object")
    return value


class McpClient:
    """Call one stateless direct MCP endpoint."""

    def __init__(self, url: str, token: str):
        """Initialize the client."""
        self.url = url
        self.token = token

    def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Send one MCP request."""
        request = urllib.request.Request(
            self.url,
            method="POST",
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "MCP-Protocol-Version": "2025-11-25",
            },
            data=json.dumps(payload).encode("utf-8"),
        )
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return parse_mcp_response(response.read(), response.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as exc:
            exc.read(4096)
            raise HttpError(exc.code, f"MCP {payload.get('method')}") from exc

    def initialize(self) -> None:
        """Initialize the MCP connection."""
        response = self.send(
            {
                "jsonrpc": "2.0",
                "id": "verify-initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "power-wiki-direct-verifier", "version": "1"},
                },
            }
        )
        if not response or "result" not in response:
            raise RuntimeError("MCP initialize returned no result")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def tools(self) -> list[dict[str, Any]]:
        """List MCP tools."""
        response = self.send({"jsonrpc": "2.0", "id": "verify-tools", "method": "tools/list", "params": {}})
        return response.get("result", {}).get("tools", []) if response else []

    def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one MCP tool and require a successful tool result."""
        response = self.send(
            {
                "jsonrpc": "2.0",
                "id": f"call-{uuid.uuid4().hex}",
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            }
        )
        result = response.get("result", {}) if response else {}
        if result.get("isError") or not isinstance(result.get("content"), list):
            raise RuntimeError(f"MCP tool failed: {tool}")
        return result


def content_json(result: dict[str, Any]) -> Any:
    """Parse JSON from the first MCP text block."""
    content = result.get("content", [])
    if not content or not isinstance(content[0], dict) or not isinstance(content[0].get("text"), str):
        raise RuntimeError("MCP tool result contained no text")
    return json.loads(content[0]["text"])


def tool_by_suffix(tools: list[dict[str, Any]], suffix: str) -> str:
    """Return one tool name by normalized suffix."""
    for tool in tools:
        name = str(tool.get("name", ""))
        if name.replace("-", "_").endswith(suffix):
            return name
    raise RuntimeError(f"MCP tool not found: {suffix}")


def expect_mcp_status(url: str, token: str | None, expected: set[int], label: str) -> int:
    """Assert the HTTP status for one initialize request."""
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-11-25",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url,
        method="POST",
        headers=headers,
        data=json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "deny-path",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "deny-path", "version": "1"},
                },
            }
        ).encode("utf-8"),
    )
    error_body = ""
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        error_body = exc.read(4096).decode("utf-8", errors="replace")
    if status not in expected:
        raise RuntimeError(
            f"MCP {label} deny path returned HTTP {status}; expected {sorted(expected)}; body={error_body}"
        )
    return status


def register_dcr_client(auth_url: str, realm: str) -> str:
    """Verify allowed and rejected dynamic client registrations."""
    endpoint = (
        f"{auth_url.rstrip('/')}/realms/{urllib.parse.quote(realm)}/"
        "clients-registrations/openid-connect"
    )
    allowed = http_json(
        "POST",
        endpoint,
        {
            "client_name": "Direct Power Wiki ChatGPT verification",
            "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "openid profile email offline_access mcp:tools",
        },
    )
    client_id = allowed.get("client_id") if isinstance(allowed, dict) else None
    if not isinstance(client_id, str) or not client_id:
        raise RuntimeError("Allowed DCR request returned no client_id")
    try:
        http_json(
            "POST",
            endpoint,
            {
                "client_name": "Rejected direct Power Wiki client",
                "redirect_uris": ["https://evil.example/callback"],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
        )
    except HttpError as exc:
        if exc.status not in {400, 403}:
            raise
    else:
        raise RuntimeError("Keycloak accepted an untrusted DCR redirect URI")
    return client_id


def main() -> int:
    """Run complete direct OAuth and Wiki verification."""
    secrets_dir = Path(required_env("POWER_WIKI_AUTH_SECRETS_DIR", "./runtime/auth-secrets"))
    keycloak_url = required_env("KEYCLOAK_INTERNAL_URL", "http://127.0.0.1:8053")
    resource_url = required_env("POWER_WIKI_RESOURCE_URL")
    mcp_url = required_env("POWER_WIKI_MCP_URL", resource_url)
    realm = required_env("POWER_WIKI_KEYCLOAK_REALM", "power-wiki-direct-dev")
    if realm != "power-wiki-direct-dev" or resource_url != "https://kb.bamboo9527.top/mcp":
        raise RuntimeError("Direct verifier refuses the ContextForge production realm/resource")
    role_name = required_env("POWER_WIKI_OAUTH_ROLE", "power-wiki-operator")
    verifier_secret = read_secret(secrets_dir / "verifier-client-secret")
    verifier_password = read_secret(secrets_dir / "verifier-user-password")
    run_id = f"t621-direct-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    client_id = f"power-wiki-direct-verifier-{run_id}"
    wrong_client_id = f"power-wiki-wrong-audience-{run_id}"
    emails = {
        "allow": f"{run_id}-allow@bamboo9527.top",
        "no_role": f"{run_id}-no-role@bamboo9527.top",
    }
    keycloak = KeycloakAdmin(
        keycloak_url,
        realm,
        required_env("KEYCLOAK_ADMIN_USERNAME", "power-wiki-admin"),
        read_secret(secrets_dir / "keycloak-admin-password"),
    )
    client_internal_ids: list[str] = []
    user_ids: list[str] = []
    dcr_client_id: str | None = None
    original_page: dict[str, Any] | None = None
    allow_client: McpClient | None = None
    tools: list[dict[str, Any]] = []
    write_restored = False

    try:
        dcr_client_id = register_dcr_client(keycloak_url, realm)
        client_internal_ids.append(keycloak.create_client(client_id, verifier_secret, resource_url))
        client_internal_ids.append(
            keycloak.create_client(wrong_client_id, verifier_secret, "https://kb.bamboo9527.top/not-the-mcp-resource")
        )
        for email in emails.values():
            user_ids.append(keycloak.create_user(email, verifier_password))
        keycloak.assign_realm_role(user_ids[0], role_name)

        allow_token = keycloak.password_token(
            client_id,
            verifier_secret,
            emails["allow"],
            verifier_password,
            "openid profile email mcp:tools",
        )
        missing_scope_token = keycloak.password_token(
            client_id,
            verifier_secret,
            emails["allow"],
            verifier_password,
            "openid profile email",
        )
        missing_role_token = keycloak.password_token(
            client_id,
            verifier_secret,
            emails["no_role"],
            verifier_password,
            "openid profile email mcp:tools",
        )
        wrong_audience_token = keycloak.password_token(
            wrong_client_id,
            verifier_secret,
            emails["allow"],
            verifier_password,
            "openid profile email",
        )
        claims = jwt_claims(allow_token)
        if os.environ.get("POWER_WIKI_DEBUG_CLAIMS") == "1":
            missing_scope_claims = jwt_claims(missing_scope_token)
            claim_names = ("iss", "aud", "sub", "iat", "exp", "nbf", "scope", "realm_access", "email")
            print(
                json.dumps(
                    {
                        "allow": {"header": jwt_header(allow_token), **{name: claims.get(name) for name in claim_names}},
                        "missing_scope": {
                            "header": jwt_header(missing_scope_token),
                            **{name: missing_scope_claims.get(name) for name in claim_names},
                        },
                    },
                    sort_keys=True,
                ),
                file=os.sys.stderr,
            )
        audience = claims.get("aud")
        audience_values = [audience] if isinstance(audience, str) else audience
        if not isinstance(audience_values, list) or resource_url not in audience_values:
            raise RuntimeError("Keycloak token lacks the exact direct MCP audience")
        if role_name not in claims.get("realm_access", {}).get("roles", []):
            raise RuntimeError("Keycloak token lacks the direct Wiki operator role")

        deny_results = {
            "anonymous": expect_mcp_status(mcp_url, None, {401}, "anonymous"),
            "invalid_token": expect_mcp_status(mcp_url, "invalid-token", {401}, "invalid_token"),
            "wrong_audience": expect_mcp_status(mcp_url, wrong_audience_token, {401}, "wrong_audience"),
            "missing_scope": expect_mcp_status(mcp_url, missing_scope_token, {403}, "missing_scope"),
            "missing_role": expect_mcp_status(mcp_url, missing_role_token, {403}, "missing_role"),
        }

        allow_client = McpClient(mcp_url, allow_token)
        allow_client.initialize()
        tools = allow_client.tools()
        expected_tools = int(os.environ.get("POWER_WIKI_EXPECTED_TOOL_COUNT", "14"))
        if len(tools) != expected_tools:
            raise RuntimeError(f"Expected {expected_tools} Power Wiki tools, received {len(tools)}")
        allow_client.call(tool_by_suffix(tools, "wiki_status"), {})

        read_tool = tool_by_suffix(tools, "wiki_read_page")
        update_tool = tool_by_suffix(tools, "wiki_update_page")
        original_page = content_json(allow_client.call(read_tool, {"path": TEST_PAGE}))
        marker = f"<!-- {run_id} -->"
        allow_client.call(update_tool, {"pagePath": TEST_PAGE, "bodyAppend": f"\n\n{marker}"})
        changed = content_json(allow_client.call(read_tool, {"path": TEST_PAGE}))
        if marker not in str(changed.get("body", "")):
            raise RuntimeError("Power Wiki write marker was not present after write")
        allow_client.call(update_tool, {"pagePath": TEST_PAGE, "bodyReplace": original_page["body"]})
        restored = content_json(allow_client.call(read_tool, {"path": TEST_PAGE}))
        if restored != original_page:
            raise RuntimeError("Power Wiki test page did not return to its original content")
        write_restored = True
        original_hash = hashlib.sha256(
            json.dumps(original_page, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        print(
            json.dumps(
                {
                    "status": "ok",
                    "path": "direct_power_llmwiki",
                    "dcr": "allowed_and_untrusted_redirect_rejected",
                    "deny_paths": deny_results,
                    "issuer": claims.get("iss"),
                    "audience": resource_url,
                    "role": role_name,
                    "tools": len(tools),
                    "write_page": TEST_PAGE,
                    "write_restored": True,
                    "restored_sha256": original_hash,
                },
                sort_keys=True,
            )
        )
        return 0
    finally:
        if original_page is not None and allow_client is not None and not write_restored:
            try:
                update_tool = tool_by_suffix(tools or allow_client.tools(), "wiki_update_page")
                allow_client.call(update_tool, {"pagePath": TEST_PAGE, "bodyReplace": original_page["body"]})
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: direct Power Wiki test-page restore failed: {error}", file=os.sys.stderr)
        for user_id in user_ids:
            try:
                keycloak.request("DELETE", f"/users/{urllib.parse.quote(user_id)}")
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: Keycloak direct verification-user cleanup failed: {error}", file=os.sys.stderr)
        for internal_id in client_internal_ids:
            try:
                keycloak.request("DELETE", f"/clients/{urllib.parse.quote(internal_id)}")
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: Keycloak direct verification-client cleanup failed: {error}", file=os.sys.stderr)
        if dcr_client_id:
            try:
                dcr_client = keycloak.client(dcr_client_id)
                if dcr_client:
                    keycloak.request("DELETE", f"/clients/{urllib.parse.quote(str(dcr_client['id']))}")
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: Keycloak DCR verification-client cleanup failed: {error}", file=os.sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # pylint: disable=broad-exception-caught
        print(f"Direct OAuth verification failed: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error
