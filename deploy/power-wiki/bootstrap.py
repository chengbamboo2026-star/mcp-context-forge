#!/usr/bin/env python3
"""Idempotently register Power LLM Wiki in a ContextForge instance."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def required_env(name: str) -> str:
    """Return one required environment value."""
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is empty: {name}")
    return value


def collection(payload: Any, key: str) -> list[dict[str, Any]]:
    """Return dictionaries from a list or paginated response."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        values = payload.get(key, [])
        if isinstance(values, list):
            return [item for item in values if isinstance(item, dict)]
    return []


def entity_gateway_id(entity: dict[str, Any]) -> str | None:
    """Return a gateway ID from supported API field names."""
    return entity.get("gatewayId") or entity.get("gateway_id") or entity.get("mcpServerId") or entity.get("mcp_server_id")


class ApiClient:
    """Call ContextForge JSON API endpoints."""

    def __init__(self, base_url: str, token: str):
        """Initialize the API client."""
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, Any] | None = None,
        *,
        allow_not_found: bool = False,
        allow_conflict: bool = False,
    ) -> Any:
        """Send one JSON API request."""
        url = f"{self.base_url}{path}"
        request = urllib.request.Request(url, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Content-Type", "application/json")
        if data is not None:
            request.data = json.dumps(data).encode("utf-8")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = response.read()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as exc:
            if allow_not_found and exc.code == 404:
                return None
            if allow_conflict and exc.code == 409:
                exc.read(2048)
                return None
            # ContextForge validation bodies can echo rejected input. Gateway
            # create/update payloads contain the upstream bearer token, so never
            # copy response bodies into bootstrap logs.
            exc.read(2048)
            raise RuntimeError(f"ContextForge {method} {path} failed with HTTP {exc.code}") from exc


def wait_for_health(base_url: str) -> None:
    """Wait until ContextForge reports a healthy status."""
    health_url = f"{base_url.rstrip('/')}/health"
    for attempt in range(1, 61):
        try:
            with urllib.request.urlopen(health_url, timeout=3) as response:
                payload = json.load(response)
                if response.status == 200 and payload.get("status") == "healthy":
                    return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        print(f"Waiting for ContextForge health ({attempt}/60)", flush=True)
        time.sleep(2)
    raise RuntimeError("ContextForge did not become healthy within 120 seconds")


def create_admin_token() -> str:
    """Create a short-lived platform administrator token."""
    command = [
        sys.executable,
        "-m",
        "mcpgateway.utils.create_jwt_token",
        "--username",
        required_env("PLATFORM_ADMIN_EMAIL"),
        "--admin",
        "--exp",
        "30",
        "--secret",
        required_env("JWT_SECRET_KEY"),
        "--algo",
        "HS256",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    token = result.stdout.strip()
    if not token:
        raise RuntimeError("ContextForge JWT utility returned an empty token")
    return token


def build_gateway_payload(service_token: str) -> dict[str, Any]:
    """Build the Power Wiki gateway request."""
    return {
        "name": os.environ.get("POWER_WIKI_GATEWAY_NAME", "llm_wike_power"),
        "url": os.environ.get("POWER_WIKI_UPSTREAM_URL", "http://power-llmwiki:8060/mcp"),
        "description": "Power LLM Wiki MCP upstream",
        "transport": "STREAMABLEHTTP",
        "auth_type": "bearer",
        "auth_token": service_token,
        "visibility": "public",
        "identity_propagation": {
            "enabled": True,
            # v1.1.2 pooled sessions carry their fresh, request-scoped JWS in
            # MCP _meta while direct calls can also use the HTTP header.
            "mode": "both",
            "headers_prefix": "X-Forwarded-User",
            "sign_claims": True,
        },
    }


def oidc_issuer() -> str:
    """Return the configured OAuth issuer without a trailing slash."""
    return required_env("POWER_WIKI_OIDC_ISSUER").rstrip("/")


def build_provider_payload(client_secret: str) -> dict[str, Any]:
    """Build the external Keycloak provider request."""
    issuer = oidc_issuer()
    return {
        "id": os.environ.get("POWER_WIKI_OIDC_PROVIDER_ID", "keycloak-power-wiki"),
        "name": "Power Wiki Keycloak",
        "display_name": "Power Wiki",
        "provider_type": "oidc",
        "client_id": os.environ.get("POWER_WIKI_OIDC_CLIENT_ID", "contextforge-power-wiki"),
        "client_secret": client_secret,
        "authorization_url": f"{issuer}/protocol/openid-connect/auth",
        "token_url": f"{issuer}/protocol/openid-connect/token",
        "userinfo_url": f"{issuer}/protocol/openid-connect/userinfo",
        "issuer": issuer,
        "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
        "scope": "openid profile email offline_access mcp:tools",
        "trusted_domains": [],
        "auto_create_users": False,
        "team_mapping": {},
        "provider_metadata": {},
        "trusted_for_api_auth": True,
        "api_audience": required_env("POWER_WIKI_RESOURCE_URL"),
    }


def build_operator_role_payload() -> dict[str, Any]:
    """Build the minimum Power Wiki operator role."""
    return {
        "name": os.environ.get("POWER_WIKI_OPERATOR_ROLE", "power_wiki_operator"),
        "description": "Use the Power Wiki virtual server and its tools",
        "scope": "team",
        "permissions": ["servers.use", "tools.read", "tools.execute"],
        "is_system_role": False,
    }


def build_server_payload(tool_ids: list[str], resource_ids: list[str], prompt_ids: list[str], team_id: str) -> dict[str, Any]:
    """Build the Power Wiki virtual server request."""
    server_id = os.environ.get("POWER_WIKI_SERVER_ID", "73c72592dd9c447d86b230930e20722d")
    return {
        "id": server_id,
        "name": os.environ.get("POWER_WIKI_SERVER_NAME", "power_ai"),
        "description": "Power AI virtual MCP server backed by Power LLM Wiki",
        "associated_tools": tool_ids,
        "associated_resources": resource_ids,
        "associated_prompts": prompt_ids,
        "team_id": team_id,
        "visibility": "public",
        "oauth_enabled": True,
        "oauth_config": {
            "authorization_servers": [oidc_issuer()],
            "resource": required_env("POWER_WIKI_RESOURCE_URL"),
            "scopes_supported": ["openid", "profile", "email", "offline_access", "mcp:tools"],
        },
    }


def reconcile_provider(api: ApiClient, payload: dict[str, Any]) -> None:
    """Create or update the external Keycloak provider."""
    provider_id = urllib.parse.quote(str(payload["id"]), safe="")
    existing = api.request("GET", f"/v1/auth/sso/admin/providers/{provider_id}", allow_not_found=True)
    if existing is None:
        api.request("POST", "/v1/auth/sso/admin/providers", payload)
        print(f"Created SSO provider {payload['id']}", flush=True)
        return
    update = dict(payload)
    update.pop("id", None)
    api.request("PUT", f"/v1/auth/sso/admin/providers/{provider_id}", update)
    print(f"Updated SSO provider {payload['id']}", flush=True)


def reconcile_operator(api: ApiClient) -> str:
    """Provision and validate the non-admin OAuth operator."""
    email = os.environ.get("POWER_WIKI_OPERATOR_EMAIL", "power-wiki-operator@bamboo9527.top").strip().lower()
    provider_id = os.environ.get("POWER_WIKI_OIDC_PROVIDER_ID", "keycloak-power-wiki")
    encoded_email = urllib.parse.quote(email, safe="")
    existing = api.request("GET", f"/v1/auth/email/admin/users/{encoded_email}", allow_not_found=True)
    if existing is None:
        api.request(
            "POST",
            "/v1/admin/users/sso",
            {
                "email": email,
                "auth_provider": provider_id,
                "full_name": "Power Wiki Operator",
                "is_admin": False,
                "is_active": True,
            },
        )
        existing = api.request("GET", f"/v1/auth/email/admin/users/{encoded_email}")
    if existing.get("is_admin") is not False or existing.get("is_active") is not True:
        raise RuntimeError("Power Wiki operator must be an active non-admin user")
    if existing.get("auth_provider") != provider_id:
        raise RuntimeError("Power Wiki operator is bound to a different authentication provider")
    return email


def reconcile_team(api: ApiClient, operator_email: str) -> str:
    """Create the dedicated operator team and ensure membership."""
    team_name = os.environ.get("POWER_WIKI_OPERATOR_TEAM", "Power Wiki Operators")
    teams = collection(api.request("GET", "/v1/teams/?limit=500&include_pagination=false"), "teams")
    team = next((item for item in teams if item.get("name") == team_name), None)
    if team is None:
        team = api.request(
            "POST",
            "/v1/teams/",
            {
                "name": team_name,
                "description": "Access scope for the Power Wiki MCP server",
                "visibility": "private",
                "max_members": 10,
                "members": [{"email": operator_email, "role": "member"}],
            },
        )
    team_id = str(team["id"])
    members = collection(api.request("GET", f"/v1/teams/{team_id}/members?limit=500&include_pagination=false"), "members")
    if not any(str(item.get("user_email", "")).lower() == operator_email for item in members):
        api.request("POST", f"/v1/teams/{team_id}/members", {"email": operator_email, "role": "member"})
    return team_id


def reconcile_operator_role(api: ApiClient, operator_email: str, team_id: str) -> str:
    """Replace every operator assignment with the minimum team-scoped role."""
    role_payload = build_operator_role_payload()
    roles = collection(api.request("GET", "/v1/rbac/roles"), "roles")
    role = next((item for item in roles if item.get("name") == role_payload["name"]), None)
    if role is None:
        role = api.request("POST", "/v1/rbac/roles", role_payload)
    else:
        role_id = str(role["id"])
        role = api.request(
            "PUT",
            f"/v1/rbac/roles/{role_id}",
            {
                "description": role_payload["description"],
                "permissions": role_payload["permissions"],
                "is_active": True,
            },
        )
    role_id = str(role["id"])
    encoded_email = urllib.parse.quote(operator_email, safe="")
    assignments = collection(api.request("GET", f"/v1/rbac/users/{encoded_email}/roles?active_only=true"), "roles")
    for assignment in assignments:
        assigned_role_id = str(assignment.get("role_id"))
        assignment_scope = str(assignment.get("scope"))
        assignment_scope_id = assignment.get("scope_id")
        if assigned_role_id == role_id and assignment_scope == "team" and assignment_scope_id == team_id:
            continue
        query_values = {"scope": assignment_scope}
        if assignment_scope_id:
            query_values["scope_id"] = str(assignment_scope_id)
        query = urllib.parse.urlencode(query_values)
        api.request("DELETE", f"/v1/rbac/users/{encoded_email}/roles/{urllib.parse.quote(assigned_role_id, safe='')}?{query}")
    assignments = collection(api.request("GET", f"/v1/rbac/users/{encoded_email}/roles?active_only=true"), "roles")
    if not any(
        str(item.get("role_id")) == role_id and item.get("scope") == "team" and item.get("scope_id") == team_id
        for item in assignments
    ):
        api.request(
            "POST",
            f"/v1/rbac/users/{encoded_email}/roles",
            {"role_id": role_id, "scope": "team", "scope_id": team_id},
        )
    final_assignments = collection(api.request("GET", f"/v1/rbac/users/{encoded_email}/roles?active_only=true"), "roles")
    if len(final_assignments) != 1:
        raise RuntimeError("Power Wiki operator has assignments beyond the minimum team role")
    only_assignment = final_assignments[0]
    if str(only_assignment.get("role_id")) != role_id or only_assignment.get("scope") != "team" or only_assignment.get("scope_id") != team_id:
        raise RuntimeError("Power Wiki operator minimum role assignment does not match the dedicated team")
    return role_id


def reconcile_gateway(api: ApiClient, payload: dict[str, Any]) -> str:
    """Create or update the Power Wiki gateway."""
    gateways = collection(api.request("GET", "/gateways"), "gateways")
    existing = next((item for item in gateways if item.get("name") == payload["name"]), None)
    if existing:
        gateway_id = str(existing["id"])
        api.request("PUT", f"/gateways/{gateway_id}", payload)
        print(f"Updated Power Wiki gateway {gateway_id}", flush=True)
        return gateway_id

    created = api.request("POST", "/gateways", payload)
    gateway_id = str(created["id"])
    print(f"Created Power Wiki gateway {gateway_id}", flush=True)
    return gateway_id


def refresh_gateway(api: ApiClient, gateway_id: str) -> None:
    """Refresh the Power Wiki gateway catalog."""
    path = f"/gateways/{urllib.parse.quote(gateway_id)}/tools/refresh?include_resources=true&include_prompts=true"
    for attempt in range(1, 31):
        try:
            api.request("POST", path)
            return
        except RuntimeError as exc:
            if "HTTP 409" not in str(exc) or attempt == 30:
                raise
            time.sleep(2)


def gateway_catalog(api: ApiClient, gateway_id: str) -> tuple[list[str], list[str], list[str]]:
    """Return IDs for the synchronized gateway catalog."""
    for attempt in range(1, 61):
        tools = collection(api.request("GET", "/tools"), "tools")
        selected_tools = [item for item in tools if entity_gateway_id(item) == gateway_id]
        if selected_tools:
            resources = collection(api.request("GET", "/resources"), "resources")
            prompts = collection(api.request("GET", "/prompts"), "prompts")
            return (
                [str(item["id"]) for item in selected_tools],
                [str(item["id"]) for item in resources if entity_gateway_id(item) == gateway_id],
                [str(item["id"]) for item in prompts if entity_gateway_id(item) == gateway_id],
            )
        print(f"Waiting for Power Wiki catalog sync ({attempt}/60)", flush=True)
        time.sleep(2)
    raise RuntimeError("Power Wiki tools did not synchronize within 120 seconds")


def reconcile_server(api: ApiClient, payload: dict[str, Any]) -> dict[str, Any]:
    """Create or update the Power Wiki virtual server."""
    server_id = str(payload["id"])
    existing = api.request("GET", f"/servers/{server_id}", allow_not_found=True)
    if existing is None:
        api.request("POST", "/servers", {"server": payload})
        print(f"Created Power Wiki virtual server {server_id}", flush=True)
        return api.request("GET", f"/servers/{server_id}")

    update_payload = dict(payload)
    update_payload.pop("id", None)
    api.request("PUT", f"/servers/{server_id}", update_payload)
    print(f"Updated Power Wiki virtual server {server_id}", flush=True)
    return api.request("GET", f"/servers/{server_id}")


def approve_server_oauth(api: ApiClient, server: dict[str, Any]) -> None:
    """Approve the current virtual-server OAuth generation."""
    server_id = str(server["id"])
    version = server.get("version")
    if not isinstance(version, int):
        raise RuntimeError("Power Wiki virtual server returned no integer version")
    api.request("POST", f"/servers/{server_id}/oauth/approve", {"version": version})
    approved = api.request("GET", f"/servers/{server_id}")
    if approved.get("oauthEnabled") is not True or approved.get("oauthConfigApproved") is not True:
        raise RuntimeError("Power Wiki OAuth configuration is not approved")


def main() -> int:
    """Reconcile the complete Power Wiki registration."""
    base_url = os.environ.get("CONTEXTFORGE_URL", "http://gateway:4444")
    wait_for_health(base_url)
    api = ApiClient(base_url, create_admin_token())

    reconcile_provider(api, build_provider_payload(required_env("POWER_WIKI_OIDC_CLIENT_SECRET")))
    operator_email = reconcile_operator(api)
    team_id = reconcile_team(api, operator_email)
    reconcile_operator_role(api, operator_email, team_id)

    gateway_payload = build_gateway_payload(required_env("POWER_WIKI_SERVICE_TOKEN"))
    gateway_id = reconcile_gateway(api, gateway_payload)
    refresh_gateway(api, gateway_id)
    tool_ids, resource_ids, prompt_ids = gateway_catalog(api, gateway_id)

    expected_tool_count = int(os.environ.get("POWER_WIKI_EXPECTED_TOOL_COUNT", "14"))
    if len(tool_ids) != expected_tool_count:
        raise RuntimeError(f"Expected {expected_tool_count} Power Wiki tools, synchronized {len(tool_ids)}")

    server_payload = build_server_payload(tool_ids, resource_ids, prompt_ids, team_id)
    server = reconcile_server(api, server_payload)
    approve_server_oauth(api, server)
    print(
        f"Power Wiki registration complete: {len(tool_ids)} tools, "
        f"{len(resource_ids)} resources, {len(prompt_ids)} prompts; OAuth and minimum RBAC enabled",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # pylint: disable=broad-exception-caught
        print(f"Power Wiki registration failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
