#!/usr/bin/env python3
"""Configure the Power Wiki OAuth realm without logging secrets."""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request


REGISTRATION_POLICY_TYPE = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
DIRECT_REALM = "power-wiki-direct-dev"
DIRECT_RESOURCE_URL = "https://kb.bamboo9527.top/mcp"
CONTEXTFORGE_RESOURCE_URL = (
    "https://kb.bamboo9527.top/servers/73c72592dd9c447d86b230930e20722d/mcp"
)


def required_env(name: str, default: str | None = None) -> str:
    """Return one required environment value."""
    value = os.environ.get(name, default or "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is empty: {name}")
    return value


def validate_profile(realm: str, resource_url: str) -> None:
    """Prevent the direct development profile from changing production OAuth."""
    if realm != DIRECT_REALM or resource_url != DIRECT_RESOURCE_URL:
        raise RuntimeError(
            "Direct profile requires the power-wiki-direct-dev realm and direct resource"
        )


def read_secret(path: str) -> str:
    """Read one nonempty secret from a file."""
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value:
        raise RuntimeError(f"Required secret file is empty: {path}")
    return value


class JsonClient:
    """Call JSON and form HTTP endpoints."""

    def __init__(self, base_url: str, token: str | None = None):
        """Initialize the client."""
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self,
        method: str,
        path: str,
        data: Any = None,
        *,
        form: bool = False,
        allowed: tuple[int, ...] = (200, 201, 204),
    ) -> Any:
        """Send one request and suppress response bodies on failure."""
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = None
        if data is not None:
            if form:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                body = urllib.parse.urlencode(data).encode("utf-8")
            else:
                headers["Content-Type"] = "application/json"
                body = json.dumps(data).encode("utf-8")
        request = urllib.request.Request(f"{self.base_url}{path}", method=method, headers=headers, data=body)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                if response.status not in allowed:
                    raise RuntimeError(f"HTTP {method} {path} returned {response.status}")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            exc.read(4096)
            if exc.code in allowed:
                return None
            raise RuntimeError(f"HTTP {method} {path} failed with status {exc.code}") from exc


def wait_for_keycloak(base_url: str) -> None:
    """Wait for the Keycloak HTTP endpoint."""
    health_url = f"{base_url.rstrip('/')}/realms/master"
    for attempt in range(1, 61):
        try:
            with urllib.request.urlopen(health_url, timeout=3) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        print(f"Waiting for Keycloak health ({attempt}/60)", flush=True)
        time.sleep(2)
    raise RuntimeError("Keycloak did not become ready within 120 seconds")


def admin_token(base_url: str, username: str, password: str) -> str:
    """Get a short-lived Keycloak administrator token."""
    client = JsonClient(base_url)
    response = client.request(
        "POST",
        "/realms/master/protocol/openid-connect/token",
        {
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        form=True,
    )
    token = response.get("access_token") if isinstance(response, dict) else None
    if not isinstance(token, str) or not token:
        raise RuntimeError("Keycloak administrator login returned no access token")
    return token


def realm_payload(realm: str) -> dict[str, Any]:
    """Return the security settings for the Power Wiki realm."""
    return {
        "realm": realm,
        "displayName": "Power Wiki",
        "enabled": True,
        "sslRequired": "external",
        "registrationAllowed": False,
        "registrationEmailAsUsername": False,
        "editUsernameAllowed": False,
        "resetPasswordAllowed": False,
        "rememberMe": True,
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "verifyEmail": False,
        "bruteForceProtected": True,
        "permanentLockout": False,
        "failureFactor": 5,
        "waitIncrementSeconds": 60,
        "maxFailureWaitSeconds": 900,
        "maxDeltaTimeSeconds": 43200,
        "accessTokenLifespan": 600,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 28800,
        "offlineSessionIdleTimeout": 2592000,
        "offlineSessionMaxLifespanEnabled": True,
        "offlineSessionMaxLifespan": 5184000,
        "revokeRefreshToken": True,
        "refreshTokenMaxReuse": 0,
    }


def ensure_realm(api: JsonClient, realm: str) -> dict[str, Any]:
    """Create or update the Power Wiki realm."""
    path = f"/admin/realms/{urllib.parse.quote(realm)}"
    try:
        current = api.request("GET", path)
    except RuntimeError as exc:
        if "status 404" not in str(exc):
            raise
        api.request("POST", "/admin/realms", realm_payload(realm))
        current = api.request("GET", path)
    update = dict(current)
    update.update(realm_payload(realm))
    api.request("PUT", path, update)
    return api.request("GET", path)


def audience_mapper(resource_url: str) -> dict[str, Any]:
    """Return the access-token audience mapper."""
    return {
        "name": "Power Wiki MCP resource audience",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "consentRequired": False,
        "config": {
            "included.client.audience": resource_url,
            "access.token.claim": "true",
            "id.token.claim": "false",
            "userinfo.token.claim": "false",
            "introspection.token.claim": "true",
        },
    }


def ensure_client_scope(api: JsonClient, realm: str, resource_url: str) -> str:
    """Create or update the mcp:tools client scope."""
    base = f"/admin/realms/{urllib.parse.quote(realm)}/client-scopes"
    scopes = api.request("GET", base)
    existing = next((item for item in scopes if item.get("name") == "mcp:tools"), None)
    payload = {
        "name": "mcp:tools",
        "description": "Access the Power Wiki MCP tools",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "true"},
    }
    if existing:
        scope_id = str(existing["id"])
        api.request("PUT", f"{base}/{urllib.parse.quote(scope_id)}", payload)
    else:
        api.request("POST", base, payload)
        scopes = api.request("GET", base)
        existing = next((item for item in scopes if item.get("name") == "mcp:tools"), None)
        if not existing:
            raise RuntimeError("Keycloak did not create the mcp:tools client scope")
        scope_id = str(existing["id"])
    mapper_base = f"{base}/{urllib.parse.quote(scope_id)}/protocol-mappers/models"
    mapper_payload = audience_mapper(resource_url)
    mappers = api.request("GET", mapper_base)
    current_mapper = next((item for item in mappers if item.get("name") == mapper_payload["name"]), None)
    if current_mapper:
        api.request(
            "PUT",
            f"{mapper_base}/{urllib.parse.quote(str(current_mapper['id']))}",
            mapper_payload,
        )
    else:
        api.request("POST", mapper_base, mapper_payload)
    verified = api.request("GET", mapper_base)
    readback = next((item for item in verified if item.get("name") == mapper_payload["name"]), None)
    if not readback or readback.get("config", {}).get("included.client.audience") != resource_url:
        raise RuntimeError("Keycloak audience mapper readback did not match the exact resource")
    return scope_id


def client_by_id(api: JsonClient, realm: str, client_id: str) -> dict[str, Any] | None:
    """Return one Keycloak client by clientId."""
    query = urllib.parse.urlencode({"clientId": client_id})
    clients = api.request("GET", f"/admin/realms/{urllib.parse.quote(realm)}/clients?{query}")
    return next((item for item in clients if item.get("clientId") == client_id), None)


def ensure_client(api: JsonClient, realm: str, payload: dict[str, Any]) -> str:
    """Create or update one Keycloak client."""
    base = f"/admin/realms/{urllib.parse.quote(realm)}/clients"
    existing = client_by_id(api, realm, str(payload["clientId"]))
    if existing:
        internal_id = str(existing["id"])
        update = dict(existing)
        update.update(payload)
        api.request("PUT", f"{base}/{urllib.parse.quote(internal_id)}", update)
        return internal_id
    api.request("POST", base, payload)
    created = client_by_id(api, realm, str(payload["clientId"]))
    if not created:
        raise RuntimeError(f"Keycloak did not create client: {payload['clientId']}")
    return str(created["id"])


def ensure_clients(
    api: JsonClient,
    realm: str,
    resource_url: str,
) -> None:
    """Create the Power Wiki bearer-only resource client."""
    ensure_client(
        api,
        realm,
        {
            "clientId": resource_url,
            "name": "Power Wiki MCP resource",
            "enabled": True,
            "protocol": "openid-connect",
            "bearerOnly": True,
            "publicClient": False,
            "standardFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "attributes": {"resource_url": resource_url},
        },
    )
    conflicting = client_by_id(api, realm, CONTEXTFORGE_RESOURCE_URL)
    if conflicting:
        api.request(
            "DELETE",
            f"/admin/realms/{urllib.parse.quote(realm)}/clients/"
            f"{urllib.parse.quote(str(conflicting['id']))}",
        )


def ensure_realm_role(api: JsonClient, realm: str, role_name: str) -> dict[str, Any]:
    """Create or update the exact realm role required by the Wiki."""
    encoded_realm = urllib.parse.quote(realm)
    encoded_role = urllib.parse.quote(role_name, safe="")
    path = f"/admin/realms/{encoded_realm}/roles/{encoded_role}"
    try:
        current = api.request("GET", path)
        update = dict(current)
        update.update({"name": role_name, "description": "Use all Power Wiki MCP tools"})
        api.request("PUT", path, update)
    except RuntimeError as exc:
        if "status 404" not in str(exc):
            raise
        api.request(
            "POST",
            f"/admin/realms/{encoded_realm}/roles",
            {"name": role_name, "description": "Use all Power Wiki MCP tools"},
        )
    return api.request("GET", path)


def ensure_operator(api: JsonClient, realm: str, email: str, initial_password: str) -> str:
    """Create the non-admin OAuth operator once."""
    base = f"/admin/realms/{urllib.parse.quote(realm)}/users"
    query = urllib.parse.urlencode({"username": email, "exact": "true"})
    users = api.request("GET", f"{base}?{query}")
    existing = next((item for item in users if str(item.get("username", "")).lower() == email.lower()), None)
    if existing:
        update = dict(existing)
        update.update({"username": email, "email": email, "enabled": True, "emailVerified": True})
        api.request("PUT", f"{base}/{urllib.parse.quote(str(existing['id']))}", update)
        return str(existing["id"])
    api.request(
        "POST",
        base,
        {
            "username": email,
            "email": email,
            "enabled": True,
            "emailVerified": True,
            "requiredActions": ["UPDATE_PASSWORD"],
            "credentials": [{"type": "password", "value": initial_password, "temporary": True}],
        },
    )
    users = api.request("GET", f"{base}?{query}")
    created = next((item for item in users if str(item.get("username", "")).lower() == email.lower()), None)
    if not created:
        raise RuntimeError("Keycloak did not create the Power Wiki operator")
    return str(created["id"])


def ensure_operator_role(
    api: JsonClient,
    realm: str,
    user_id: str,
    role: dict[str, Any],
) -> None:
    """Assign the required realm role to the operator only."""
    path = (
        f"/admin/realms/{urllib.parse.quote(realm)}/users/"
        f"{urllib.parse.quote(user_id)}/role-mappings/realm"
    )
    roles = api.request("GET", path)
    if any(item.get("name") == role.get("name") for item in roles):
        return
    api.request("POST", path, [role])


def ensure_policy_component(
    api: JsonClient,
    realm: str,
    realm_id: str,
    provider_id: str,
    name: str,
    config: dict[str, list[str]],
) -> None:
    """Create or update one anonymous registration policy."""
    query = urllib.parse.urlencode({"parent": realm_id, "type": REGISTRATION_POLICY_TYPE})
    base = f"/admin/realms/{urllib.parse.quote(realm)}/components"
    components = api.request("GET", f"{base}?{query}")
    existing = next(
        (
            item
            for item in components
            if item.get("providerId") == provider_id and item.get("subType") == "anonymous"
        ),
        None,
    )
    payload = {
        "name": name,
        "parentId": realm_id,
        "providerId": provider_id,
        "providerType": REGISTRATION_POLICY_TYPE,
        "subType": "anonymous",
        "config": config,
    }
    if existing:
        component_id = str(existing["id"])
        update = dict(existing)
        update.update(payload)
        api.request("PUT", f"{base}/{urllib.parse.quote(component_id)}", update)
    else:
        api.request("POST", base, payload)


def ensure_registration_policies(api: JsonClient, realm: str, realm_id: str) -> None:
    """Restrict anonymous dynamic client registration."""
    ensure_policy_component(
        api,
        realm,
        realm_id,
        "trusted-hosts",
        "ChatGPT trusted hosts",
        {
            "trusted-hosts": ["chatgpt.com", "*.chatgpt.com"],
            "host-sending-registration-request-must-match": ["false"],
            "client-uris-must-match": ["true"],
        },
    )
    ensure_policy_component(
        api,
        realm,
        realm_id,
        "max-clients",
        "ChatGPT client limit",
        {"max-clients": ["20"]},
    )
    ensure_policy_component(
        api,
        realm,
        realm_id,
        "allowed-client-templates",
        "Power Wiki client scopes",
        {
            "allow-default-scopes": ["true"],
            "allowed-client-scopes": ["openid", "profile", "email", "offline_access", "mcp:tools"],
        },
    )


def main() -> int:
    """Reconcile the Keycloak realm and OAuth clients."""
    base_url = required_env("KEYCLOAK_INTERNAL_URL", "http://127.0.0.1:8053")
    realm = required_env("POWER_WIKI_KEYCLOAK_REALM", "power-wiki-direct-dev")
    resource_url = required_env("POWER_WIKI_RESOURCE_URL")
    validate_profile(realm, resource_url)
    operator_role = required_env("POWER_WIKI_OAUTH_ROLE", "power-wiki-operator")
    operator_email = required_env("POWER_WIKI_OPERATOR_EMAIL", "power-wiki-operator@bamboo9527.top").lower()
    secrets_dir = Path(required_env("POWER_WIKI_AUTH_SECRETS_DIR", "./runtime/auth-secrets"))

    wait_for_keycloak(base_url)
    token = admin_token(
        base_url,
        required_env("KEYCLOAK_ADMIN_USERNAME", "power-wiki-admin"),
        read_secret(str(secrets_dir / "keycloak-admin-password")),
    )
    api = JsonClient(base_url, token)
    realm_state = ensure_realm(api, realm)
    ensure_client_scope(api, realm, resource_url)
    ensure_clients(api, realm, resource_url)
    role = ensure_realm_role(api, realm, operator_role)
    operator_id = ensure_operator(
        api,
        realm,
        operator_email,
        read_secret(str(secrets_dir / "operator-initial-password")),
    )
    ensure_operator_role(api, realm, operator_id, role)
    ensure_registration_policies(api, realm, str(realm_state["id"]))
    print(
        json.dumps(
            {
                "status": "ok",
                "realm": realm,
                "resource": resource_url,
                "operator": operator_email,
                "operator_role": operator_role,
                "dcr": "restricted",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # pylint: disable=broad-exception-caught
        print(f"Keycloak bootstrap failed: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error
