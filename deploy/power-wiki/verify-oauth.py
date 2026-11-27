#!/usr/bin/env python3
"""Verify Power Wiki OAuth, RBAC deny paths, and reversible writes."""

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
    """Read one nonempty secret."""
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"Required secret file is empty: {path}")
    return value


class HttpError(RuntimeError):
    """Represent one expected HTTP failure without its response body."""

    def __init__(self, status: int, operation: str, retry_after: float | None = None):
        """Initialize the error."""
        super().__init__(f"{operation} failed with HTTP {status}")
        self.status = status
        self.retry_after = retry_after


def http_json(
    method: str,
    url: str,
    data: Any = None,
    *,
    token: str | None = None,
    form: bool = False,
    headers: dict[str, str] | None = None,
) -> tuple[Any, dict[str, str]]:
    """Send one JSON or form request."""
    request_headers = {"Accept": "application/json", **(headers or {})}
    if token:
        request_headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        if form:
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(data).encode("utf-8")
        else:
            request_headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")
    request = urllib.request.Request(url, method=method, headers=request_headers, data=body)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return (json.loads(raw) if raw else None), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        exc.read(4096)
        retry_after = None
        try:
            retry_after = float(exc.headers.get("Retry-After", ""))
        except (TypeError, ValueError):
            pass
        raise HttpError(
            exc.code,
            f"{method} {urllib.parse.urlparse(url).path}",
            retry_after,
        ) from exc


def protected_resource_metadata_url(resource_url: str) -> str:
    """Build the RFC 9728 metadata URL for one MCP resource URL."""
    parsed = urllib.parse.urlsplit(resource_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.path.startswith("/"):
        raise RuntimeError("Power Wiki resource URL is not an absolute HTTP(S) URL")
    metadata_path = f"/.well-known/oauth-protected-resource{parsed.path.rstrip('/')}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, metadata_path, "", ""))


def authorization_server_metadata_url(issuer: str) -> str:
    """Return the RFC 8414 metadata URL for one issuer."""
    parsed = urllib.parse.urlsplit(issuer)
    metadata_path = f"/.well-known/oauth-authorization-server{parsed.path.rstrip('/')}"
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, metadata_path, "", ""))


def verify_authorization_server_metadata(metadata: Any, issuer: str, label: str) -> None:
    """Require one OpenAI-compatible authorization server document."""
    if not isinstance(metadata, dict) or metadata.get("issuer") != issuer:
        raise RuntimeError(f"{label} discovery returned the wrong issuer")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        value = metadata.get(field)
        if not isinstance(value, str) or not value.startswith(f"{issuer}/"):
            raise RuntimeError(f"{label} discovery returned an invalid {field}")
    if metadata.get("registration_endpoint") != f"{issuer}/clients-registrations/openid-connect":
        raise RuntimeError(f"{label} discovery returned an invalid registration_endpoint")
    token_auth_methods = metadata.get("token_endpoint_auth_methods_supported")
    if not isinstance(token_auth_methods, list) or "none" not in token_auth_methods:
        raise RuntimeError(f"{label} discovery omitted public PKCE token exchange")
    challenge_methods = metadata.get("code_challenge_methods_supported")
    if not isinstance(challenge_methods, list) or "S256" not in challenge_methods:
        raise RuntimeError(f"{label} discovery omitted the S256 PKCE method")
    if metadata.get("authorization_response_iss_parameter_supported") is not True:
        raise RuntimeError(f"{label} discovery omitted authorization response issuer support")


def verify_oauth_discovery(resource_url: str, issuer: str) -> dict[str, str]:
    """Require public RFC 9728 metadata and matching OIDC discovery."""
    issuer = issuer.rstrip("/")
    metadata_url = protected_resource_metadata_url(resource_url)
    metadata, _ = http_json("GET", metadata_url)
    if not isinstance(metadata, dict):
        raise RuntimeError("OAuth protected-resource metadata was not an object")
    if metadata.get("resource") != resource_url:
        raise RuntimeError("OAuth protected-resource metadata returned the wrong resource")
    authorization_servers = metadata.get("authorization_servers")
    if authorization_servers != [issuer]:
        raise RuntimeError("OAuth protected-resource metadata returned the wrong authorization server")
    if metadata.get("bearer_methods_supported") != ["header"]:
        raise RuntimeError("OAuth protected-resource metadata did not require header bearer tokens")
    scopes = metadata.get("scopes_supported")
    if not isinstance(scopes, list) or "mcp:tools" not in scopes:
        raise RuntimeError("OAuth protected-resource metadata omitted the mcp:tools scope")

    oidc_url = f"{issuer}/.well-known/openid-configuration"
    oidc, _ = http_json("GET", oidc_url)
    verify_authorization_server_metadata(oidc, issuer, "OIDC")
    authorization_metadata_url = authorization_server_metadata_url(issuer)
    authorization_metadata, _ = http_json("GET", authorization_metadata_url)
    verify_authorization_server_metadata(authorization_metadata, issuer, "RFC 8414")
    return {
        "resource_metadata": metadata_url,
        "authorization_server_metadata": authorization_metadata_url,
        "issuer": issuer,
    }


def verify_server_profile(server: dict[str, Any], server_id: str, team_id: str) -> dict[str, Any]:
    """Require the virtual server to retain its discovery and RBAC ownership profile."""
    actual_id = str(server.get("id", ""))
    actual_team_id = str(server.get("teamId") or server.get("team_id") or "")
    if actual_id != server_id:
        raise RuntimeError("Power Wiki virtual server returned the wrong ID")
    if server.get("visibility") != "public":
        raise RuntimeError("Power Wiki virtual server must remain public for RFC 9728 discovery")
    if actual_team_id != team_id:
        raise RuntimeError("Power Wiki virtual server is not owned by the dedicated operator team")
    if server.get("oauthEnabled") is not True or server.get("oauthConfigApproved") is not True:
        raise RuntimeError("Power Wiki virtual server OAuth must remain enabled and approved")
    return {"id": actual_id, "team_id": actual_team_id, "visibility": "public", "oauth_approved": True}


def jwt_claims(token: str) -> dict[str, Any]:
    """Decode unverified claims for test assertions only."""
    parts = token.split(".")
    if len(parts) != 3:
        raise RuntimeError("Access token is not a JWT")
    encoded = parts[1] + "=" * (-len(parts[1]) % 4)
    value = json.loads(base64.urlsafe_b64decode(encoded))
    if not isinstance(value, dict):
        raise RuntimeError("Access token claims are not an object")
    return value


class KeycloakAdmin:
    """Manage temporary Keycloak verification objects."""

    def __init__(self, base_url: str, realm: str, username: str, password: str):
        """Authenticate to the Keycloak administration API."""
        self.base_url = base_url.rstrip("/")
        self.realm = realm
        self.username = username
        self.password = password
        self.token = self._authenticate()

    def _authenticate(self) -> str:
        """Return a fresh Keycloak administration access token."""
        response, _ = http_json(
            "POST",
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            {
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": self.username,
                "password": self.password,
            },
            form=True,
        )
        return str(response["access_token"])

    def request(self, method: str, path: str, data: Any = None) -> Any:
        """Send one realm administration request, refreshing one expired token."""
        url = f"{self.base_url}/admin/realms/{urllib.parse.quote(self.realm)}{path}"
        try:
            value, _ = http_json(method, url, data, token=self.token)
            return value
        except HttpError as exc:
            if exc.status != 401:
                raise
        self.token = self._authenticate()
        value, _ = http_json(method, url, data, token=self.token)
        return value

    def client(self, client_id: str) -> dict[str, Any] | None:
        """Return one client by clientId."""
        query = urllib.parse.urlencode({"clientId": client_id})
        clients = self.request("GET", f"/clients?{query}")
        return next((item for item in clients if item.get("clientId") == client_id), None)

    def require_optional_client_scope(self, client_id: str, scope_name: str) -> None:
        """Require one optional scope on a Keycloak client."""
        client = self.client(client_id)
        if not client:
            raise RuntimeError("Keycloak did not retain the DCR client")
        scopes = self.request("GET", f"/clients/{urllib.parse.quote(str(client['id']))}/optional-client-scopes")
        if not any(item.get("name") == scope_name for item in scopes):
            raise RuntimeError(f"Keycloak DCR client omitted the {scope_name} scope")

    def create_verifier_client(self, client_id: str, secret: str) -> str:
        """Create a direct-grant client for this verification run."""
        existing = self.client(client_id)
        if existing:
            self.request("DELETE", f"/clients/{urllib.parse.quote(str(existing['id']))}")
        self.request(
            "POST",
            "/clients",
            {
                "clientId": client_id,
                "name": "Temporary Power Wiki verifier",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": secret,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": False,
                "fullScopeAllowed": False,
            },
        )
        created = self.client(client_id)
        if not created:
            raise RuntimeError("Keycloak did not create the verification client")
        internal_id = str(created["id"])
        client_scopes = self.request("GET", "/client-scopes")
        mcp_scope = next((item for item in client_scopes if item.get("name") == "mcp:tools"), None)
        if not mcp_scope:
            raise RuntimeError("Keycloak mcp:tools client scope is missing")
        self.request(
            "PUT",
            f"/clients/{urllib.parse.quote(internal_id)}/optional-client-scopes/{urllib.parse.quote(str(mcp_scope['id']))}",
        )
        assigned_scopes = self.request("GET", f"/clients/{urllib.parse.quote(internal_id)}/optional-client-scopes")
        if not any(item.get("name") == "mcp:tools" for item in assigned_scopes):
            raise RuntimeError("Keycloak did not assign the mcp:tools scope to the verification client")
        return internal_id

    def create_user(self, email: str, password: str) -> str:
        """Create one temporary test user."""
        query = urllib.parse.urlencode({"username": email, "exact": "true"})
        existing = self.request("GET", f"/users?{query}")
        for user in existing:
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
            raise RuntimeError("Keycloak did not create a verification user")
        return str(users[0]["id"])

    def password_token(self, client_id: str, client_secret: str, email: str, password: str, scope: str, resource: str | None = None) -> str:
        """Get a temporary user token for black-box verification."""
        form = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "password",
            "username": email,
            "password": password,
            "scope": scope,
        }
        if resource:
            form["resource"] = resource
        response, _ = http_json(
            "POST",
            f"{self.base_url}/realms/{urllib.parse.quote(self.realm)}/protocol/openid-connect/token",
            form,
            form=True,
        )
        return str(response["access_token"])


class ContextForgeAdmin:
    """Manage temporary ContextForge verification objects."""

    def __init__(self, base_url: str, email: str, password: str):
        """Authenticate to the native administration API."""
        self.base_url = base_url.rstrip("/")
        response, _ = http_json("POST", f"{self.base_url}/v1/auth/login", {"email": email, "password": password})
        self.token = str(response["access_token"])

    def request(self, method: str, path: str, data: Any = None) -> Any:
        """Send one ContextForge administration request."""
        for attempt in range(1, 10):
            try:
                value, _ = http_json(method, f"{self.base_url}{path}", data, token=self.token)
                return value
            except HttpError as exc:
                if exc.status != 429 or attempt == 9:
                    raise
                delay = exc.retry_after if exc.retry_after is not None else min(5 * attempt, 30)
                time.sleep(max(1.0, min(delay, 120.0)))
        raise RuntimeError("ContextForge request retry loop ended unexpectedly")

    def provision_sso_user(self, email: str, provider_id: str) -> None:
        """Provision one non-admin SSO user."""
        try:
            self.request(
                "POST",
                "/v1/admin/users/sso",
                {
                    "email": email,
                    "auth_provider": provider_id,
                    "full_name": f"Power Wiki verifier {email.split('@', maxsplit=1)[0][-16:]}",
                    "is_admin": False,
                    "is_active": True,
                },
            )
        except HttpError as exc:
            if exc.status != 409:
                raise

    def team_id(self, name: str) -> str:
        """Return a team ID by name."""
        teams = self.request("GET", "/v1/teams/?limit=500&include_pagination=false")
        for team in teams if isinstance(teams, list) else teams.get("teams", []):
            if team.get("name") == name:
                return str(team["id"])
        raise RuntimeError(f"ContextForge team not found: {name}")

    def role(self, name: str) -> dict[str, Any]:
        """Return a role by name."""
        roles = self.request("GET", "/v1/rbac/roles")
        for role in roles:
            if role.get("name") == name:
                return role
        raise RuntimeError(f"ContextForge role not found: {name}")

    def ensure_role(self, name: str, permissions: list[str]) -> dict[str, Any]:
        """Create or update one temporary team role."""
        roles = self.request("GET", "/v1/rbac/roles")
        existing = next((role for role in roles if role.get("name") == name), None)
        if existing:
            return self.request(
                "PUT",
                f"/v1/rbac/roles/{urllib.parse.quote(str(existing['id']))}",
                {"description": "Temporary OAuth deny-path verifier", "permissions": permissions, "is_active": True},
            )
        return self.request(
            "POST",
            "/v1/rbac/roles",
            {"name": name, "description": "Temporary OAuth deny-path verifier", "scope": "team", "permissions": permissions, "is_system_role": False},
        )

    def add_member(self, team_id: str, email: str) -> None:
        """Add one user to the verification team."""
        try:
            self.request("POST", f"/v1/teams/{team_id}/members", {"email": email, "role": "member"})
        except HttpError as exc:
            if exc.status != 409:
                raise

    def assignments(self, email: str) -> list[dict[str, Any]]:
        """Return active assignments for one user."""
        value = self.request("GET", f"/v1/rbac/users/{urllib.parse.quote(email, safe='')}/roles?active_only=true")
        return value if isinstance(value, list) else value.get("roles", [])

    def clear_roles(self, email: str) -> None:
        """Remove every active role assignment from one verification user."""
        encoded_email = urllib.parse.quote(email, safe="")
        for assignment in self.assignments(email):
            query_values = {"scope": str(assignment.get("scope"))}
            if assignment.get("scope_id"):
                query_values["scope_id"] = str(assignment["scope_id"])
            query = urllib.parse.urlencode(query_values)
            role_id = urllib.parse.quote(str(assignment["role_id"]), safe="")
            self.request("DELETE", f"/v1/rbac/users/{encoded_email}/roles/{role_id}?{query}")

    def set_team_role(self, team_id: str, email: str, role_id: str) -> None:
        """Replace team assignments with one exact role."""
        encoded_email = urllib.parse.quote(email, safe="")
        self.clear_roles(email)
        self.request(
            "POST",
            f"/v1/rbac/users/{encoded_email}/roles",
            {"role_id": role_id, "scope": "team", "scope_id": team_id},
        )
        assignments = self.assignments(email)
        if len(assignments) != 1:
            raise RuntimeError("Verification user has assignments beyond the requested team role")
        assignment = assignments[0]
        if str(assignment.get("role_id")) != role_id or assignment.get("scope") != "team" or assignment.get("scope_id") != team_id:
            raise RuntimeError("Verification user role assignment does not match the requested team role")


def parse_mcp_response(raw: bytes, content_type: str) -> dict[str, Any] | None:
    """Parse one JSON or SSE MCP response."""
    if not raw:
        return None
    text = raw.decode("utf-8")
    if "text/event-stream" in content_type:
        lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
        if not lines:
            raise RuntimeError("MCP SSE response contained no data event")
        text = lines[-1]
    value = json.loads(text)
    if not isinstance(value, dict):
        raise RuntimeError("MCP response was not a JSON object")
    return value


class McpClient:
    """Call one protected virtual MCP server."""

    def __init__(self, url: str, token: str):
        """Initialize the MCP client."""
        self.url = url
        self.token = token
        self.session_id: str | None = None

    def send(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Send one MCP request."""
        headers = {
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": "2025-11-25",
        }
        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id
        request = urllib.request.Request(self.url, method="POST", headers=headers, data=json.dumps(payload).encode("utf-8"))
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                self.session_id = response.headers.get("MCP-Session-Id") or self.session_id
                return parse_mcp_response(response.read(), response.headers.get("Content-Type", ""))
        except urllib.error.HTTPError as exc:
            exc.read(4096)
            raise HttpError(exc.code, f"MCP {payload.get('method')}") from exc

    def initialize(self) -> dict[str, Any]:
        """Initialize one MCP session."""
        result = self.send(
            {
                "jsonrpc": "2.0",
                "id": "verify-initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "power-wiki-oauth-verifier", "version": "1"},
                },
            }
        )
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        if not result or "result" not in result:
            raise RuntimeError("MCP initialize returned no result")
        return result

    def tools(self) -> list[dict[str, Any]]:
        """List MCP tools."""
        response = self.send({"jsonrpc": "2.0", "id": "verify-tools", "method": "tools/list", "params": {}})
        return response.get("result", {}).get("tools", []) if response else []

    def call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one MCP tool."""
        response = self.send(
            {"jsonrpc": "2.0", "id": f"call-{uuid.uuid4().hex}", "method": "tools/call", "params": {"name": tool, "arguments": arguments}}
        )
        result = response.get("result", {}) if response else {}
        if result.get("isError") or not isinstance(result.get("content"), list):
            raise RuntimeError(f"MCP tool failed: {tool}")
        return result

    def expect_call_denied(self, tool: str, arguments: dict[str, Any]) -> str:
        """Require one tool call to fail with an explicit permission denial."""
        try:
            response = self.send(
                {
                    "jsonrpc": "2.0",
                    "id": f"deny-{uuid.uuid4().hex}",
                    "method": "tools/call",
                    "params": {"name": tool, "arguments": arguments},
                }
            )
        except HttpError as exc:
            if exc.status == 403:
                return "http_403"
            raise
        if not response:
            raise RuntimeError("Denied MCP tool call returned no response")
        denial_text = json.dumps(response, ensure_ascii=False).lower()
        denial_terms = ("access denied", "permission", "forbidden", "not authorized")
        if "error" in response and any(term in denial_text for term in denial_terms):
            return "mcp_jsonrpc_error"
        result = response.get("result", {})
        if isinstance(result, dict) and result.get("isError") is True and any(term in denial_text for term in denial_terms):
            return "mcp_tool_error"
        raise RuntimeError("User without tools.execute did not receive an explicit permission denial")


def content_json(result: dict[str, Any]) -> Any:
    """Parse JSON from the first MCP text content block."""
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


def expect_mcp_status(url: str, token: str | None, expected: set[int]) -> int:
    """Assert the HTTP status for an initialize request."""
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {
        "jsonrpc": "2.0",
        "id": "deny-path",
        "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "deny-path", "version": "1"}},
    }
    request = urllib.request.Request(url, method="POST", headers=headers, data=json.dumps(payload).encode("utf-8"))
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            status = response.status
            response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.read(4096)
    if status not in expected:
        raise RuntimeError(f"MCP deny path returned HTTP {status}; expected {sorted(expected)}")
    return status


def register_dcr_client(auth_url: str) -> str:
    """Verify allowed and denied dynamic client registrations."""
    endpoint = f"{auth_url.rstrip('/')}/realms/power-wiki/clients-registrations/openid-connect"
    allowed, _ = http_json(
        "POST",
        endpoint,
        {
            "client_name": "Power Wiki ChatGPT verification",
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
                "client_name": "Rejected Power Wiki client",
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
    """Run the complete black-box OAuth verification."""
    secrets_dir = Path(required_env("POWER_WIKI_AUTH_SECRETS_DIR", "./runtime/auth-secrets"))
    keycloak_url = required_env("KEYCLOAK_INTERNAL_URL", "http://127.0.0.1:8053")
    contextforge_url = required_env("CONTEXTFORGE_URL", "http://127.0.0.1:8051")
    resource_url = required_env("POWER_WIKI_RESOURCE_URL")
    server_id = required_env("POWER_WIKI_SERVER_ID", "73c72592dd9c447d86b230930e20722d")
    issuer = required_env("POWER_WIKI_OIDC_ISSUER")
    provider_id = required_env("POWER_WIKI_OIDC_PROVIDER_ID", "keycloak-power-wiki")
    team_name = required_env("POWER_WIKI_OPERATOR_TEAM", "Power Wiki Operators")
    operator_role_name = required_env("POWER_WIKI_OPERATOR_ROLE", "power_wiki_operator")
    admin_email = required_env("PLATFORM_ADMIN_EMAIL", "chengzuwei20240124@outlook.com")
    contextforge_password = read_secret(Path(required_env("CONTEXTFORGE_PLATFORM_ADMIN_PASSWORD_FILE")))
    verifier_secret = read_secret(secrets_dir / "verifier-client-secret")
    verifier_password = read_secret(secrets_dir / "verifier-user-password")
    run_id = f"t621-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    client_id = f"power-wiki-verifier-{run_id}"
    emails = {
        "allow": f"{run_id}-allow@bamboo9527.top",
        "insufficient": f"{run_id}-insufficient@bamboo9527.top",
        "wrong_team": f"{run_id}-wrong-team@bamboo9527.top",
    }
    keycloak = KeycloakAdmin(
        keycloak_url,
        required_env("POWER_WIKI_KEYCLOAK_REALM", "power-wiki"),
        required_env("KEYCLOAK_ADMIN_USERNAME", "power-wiki-admin"),
        read_secret(secrets_dir / "keycloak-admin-password"),
    )
    contextforge = ContextForgeAdmin(contextforge_url, admin_email, contextforge_password)
    keycloak_user_ids: list[str] = []
    temporary_role_id: str | None = None
    dcr_client_id: str | None = None
    verifier_client_internal_id: str | None = None
    original_page: dict[str, Any] | None = None
    allow_client: McpClient | None = None
    tools: list[dict[str, Any]] = []
    write_restored = False

    try:
        discovery = verify_oauth_discovery(resource_url, issuer)
        dcr_client_id = register_dcr_client(keycloak_url)
        keycloak.require_optional_client_scope(dcr_client_id, "mcp:tools")
        verifier_client_internal_id = keycloak.create_verifier_client(client_id, verifier_secret)
        for email in emails.values():
            keycloak_user_ids.append(keycloak.create_user(email, verifier_password))
            contextforge.provision_sso_user(email, provider_id)
            contextforge.clear_roles(email)

        team_id = contextforge.team_id(team_name)
        server_profile = verify_server_profile(contextforge.request("GET", f"/servers/{server_id}"), server_id, team_id)
        operator_role = contextforge.role(operator_role_name)
        if operator_role.get("permissions") != ["servers.use", "tools.read", "tools.execute"]:
            raise RuntimeError("Power Wiki operator role has unexpected permissions")
        temporary_role = contextforge.ensure_role(f"power_wiki_verify_read_{run_id}", ["servers.use", "tools.read"])
        temporary_role_id = str(temporary_role["id"])
        contextforge.add_member(team_id, emails["allow"])
        contextforge.set_team_role(team_id, emails["allow"], str(operator_role["id"]))
        contextforge.add_member(team_id, emails["insufficient"])
        contextforge.set_team_role(team_id, emails["insufficient"], temporary_role_id)

        allow_token = keycloak.password_token(client_id, verifier_secret, emails["allow"], verifier_password, "openid profile email mcp:tools", resource_url)
        insufficient_token = keycloak.password_token(client_id, verifier_secret, emails["insufficient"], verifier_password, "openid profile email mcp:tools", resource_url)
        wrong_team_token = keycloak.password_token(client_id, verifier_secret, emails["wrong_team"], verifier_password, "openid profile email mcp:tools", resource_url)
        wrong_audience_token = keycloak.password_token(client_id, verifier_secret, emails["allow"], verifier_password, "openid profile email")
        allow_claims = jwt_claims(allow_token)
        audience = allow_claims.get("aud")
        audience_values = [audience] if isinstance(audience, str) else audience
        if not isinstance(audience_values, list) or resource_url not in audience_values:
            raise RuntimeError("Keycloak access token does not contain the exact MCP resource audience")

        deny_results = {
            "anonymous": expect_mcp_status(resource_url, None, {401}),
            "invalid_token": expect_mcp_status(resource_url, "invalid-token", {401}),
            "wrong_audience": expect_mcp_status(resource_url, wrong_audience_token, {401}),
            "wrong_team": expect_mcp_status(resource_url, wrong_team_token, {403, 404}),
        }

        insufficient_client = McpClient(resource_url, insufficient_token)
        insufficient_client.initialize()
        insufficient_tools = insufficient_client.tools()
        status_tool = tool_by_suffix(insufficient_tools, "wiki_status")
        deny_results["insufficient_permission"] = insufficient_client.expect_call_denied(status_tool, {})

        allow_client = McpClient(resource_url, allow_token)
        allow_client.initialize()
        tools = allow_client.tools()
        if len(tools) != int(os.environ.get("POWER_WIKI_EXPECTED_TOOL_COUNT", "14")):
            raise RuntimeError(f"Expected 14 Power Wiki tools, received {len(tools)}")
        status_tool = tool_by_suffix(tools, "wiki_status")
        allow_client.call(status_tool, {})

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
        original_hash = hashlib.sha256(json.dumps(original_page, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

        print(
            json.dumps(
                {
                    "status": "ok",
                    "dcr": "allowed_and_untrusted_redirect_rejected",
                    "discovery": discovery,
                    "deny_paths": deny_results,
                    "issuer": allow_claims.get("iss"),
                    "server": server_profile,
                    "audience": resource_url,
                    "tools": len(tools),
                    "write_page": TEST_PAGE,
                    "write_restored": write_restored,
                    "restored_sha256": original_hash,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 0
    finally:
        if original_page is not None and allow_client is not None and not write_restored:
            try:
                update_tool = tool_by_suffix(tools or allow_client.tools(), "wiki_update_page")
                allow_client.call(update_tool, {"pagePath": TEST_PAGE, "bodyReplace": original_page["body"]})
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: Power Wiki test-page restore failed: {error}", file=os.sys.stderr)
        team_id = None
        try:
            team_id = contextforge.team_id(team_name)
        except Exception:
            pass
        for email in emails.values():
            encoded_email = urllib.parse.quote(email, safe="")
            try:
                if team_id:
                    for assignment in contextforge.assignments(email):
                        if assignment.get("scope") == "team" and assignment.get("scope_id") == team_id:
                            query = urllib.parse.urlencode({"scope": "team", "scope_id": team_id})
                            contextforge.request(
                                "DELETE",
                                f"/v1/rbac/users/{encoded_email}/roles/{urllib.parse.quote(str(assignment['role_id']), safe='')}?{query}",
                            )
                    try:
                        contextforge.request("DELETE", f"/v1/teams/{team_id}/members/{encoded_email}")
                    except HttpError as exc:
                        if exc.status != 404:
                            raise
                try:
                    contextforge.request("DELETE", f"/v1/auth/email/admin/users/{encoded_email}")
                except HttpError as exc:
                    if exc.status != 404:
                        raise
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: ContextForge verification-user cleanup failed for {email}: {error}", file=os.sys.stderr)
        if temporary_role_id:
            try:
                contextforge.request("DELETE", f"/v1/rbac/roles/{urllib.parse.quote(temporary_role_id)}")
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: ContextForge verification-role cleanup failed: {error}", file=os.sys.stderr)
        for user_id in keycloak_user_ids:
            try:
                keycloak.request("DELETE", f"/users/{urllib.parse.quote(user_id)}")
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: Keycloak verification-user cleanup failed: {error}", file=os.sys.stderr)
        for internal_id in (verifier_client_internal_id, str(dcr_client_id or "")):
            if not internal_id:
                continue
            try:
                target = internal_id
                if internal_id == dcr_client_id:
                    dcr_client = keycloak.client(internal_id)
                    if not dcr_client:
                        continue
                    target = str(dcr_client["id"])
                keycloak.request("DELETE", f"/clients/{urllib.parse.quote(target)}")
            except Exception as error:  # pylint: disable=broad-exception-caught
                print(f"WARNING: Keycloak verification-client cleanup failed: {error}", file=os.sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # pylint: disable=broad-exception-caught
        print(f"OAuth verification failed: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error
