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
CONTEXTFORGE_REALM = "power-wiki"
CONTEXTFORGE_RESOURCE_URL = (
    "https://kb.bamboo9527.top/servers/73c72592dd9c447d86b230930e20722d/mcp"
)
DIRECT_RESOURCE_URL = "https://kb.bamboo9527.top/mcp"
CHATGPT_STABLE_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
CHATGPT_CALLBACK_PREFIX = "/connector/oauth/"


def required_env(name: str, default: str | None = None) -> str:
    """Return one required environment value."""
    value = os.environ.get(name, default or "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is empty: {name}")
    return value


def validate_profile(realm: str, resource_url: str) -> None:
    """Prevent this production profile from reconciling the direct realm."""
    if realm != CONTEXTFORGE_REALM or resource_url != CONTEXTFORGE_RESOURCE_URL:
        raise RuntimeError(
            "ContextForge profile requires the power-wiki realm and its exact server resource"
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


def ensure_realm_optional_scope(api: JsonClient, realm: str, scope_id: str) -> None:
    """Add mcp:tools to the optional scopes for new clients."""
    encoded_realm = urllib.parse.quote(realm)
    encoded_scope = urllib.parse.quote(scope_id)
    base = f"/admin/realms/{encoded_realm}"
    path = f"{base}/default-optional-client-scopes"
    assigned = api.request("GET", path)
    if not any(str(item.get("id")) == scope_id for item in assigned):
        api.request("PUT", f"{path}/{encoded_scope}")
    verified = api.request("GET", path)
    if not any(str(item.get("id")) == scope_id for item in verified):
        raise RuntimeError("Keycloak did not add mcp:tools to the optional realm scopes")


def is_chatgpt_dcr_client(client: dict[str, Any]) -> bool:
    """Return true for a public ChatGPT authorization-code client."""
    redirect_uris = client.get("redirectUris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return False
    if client.get("protocol") != "openid-connect":
        return False
    if client.get("publicClient") is not True or client.get("standardFlowEnabled") is not True:
        return False
    for value in redirect_uris:
        parsed = urllib.parse.urlsplit(str(value))
        if parsed.scheme != "https" or parsed.netloc != "chatgpt.com" or parsed.query or parsed.fragment:
            return False
        if parsed.path != urllib.parse.urlsplit(CHATGPT_STABLE_REDIRECT).path and not parsed.path.startswith(CHATGPT_CALLBACK_PREFIX):
            return False
    return True


def ensure_chatgpt_dcr_scopes(api: JsonClient, realm: str, scope_id: str) -> int:
    """Add mcp:tools to each existing ChatGPT DCR client."""
    encoded_realm = urllib.parse.quote(realm)
    clients = api.request("GET", f"/admin/realms/{encoded_realm}/clients?max=1000")
    matched = 0
    for client in clients:
        if not is_chatgpt_dcr_client(client):
            continue
        matched += 1
        client_id = urllib.parse.quote(str(client["id"]))
        scope_path = f"/admin/realms/{encoded_realm}/clients/{client_id}/optional-client-scopes"
        assigned = api.request("GET", scope_path)
        if not any(str(item.get("id")) == scope_id for item in assigned):
            api.request("PUT", f"{scope_path}/{urllib.parse.quote(scope_id)}")
        verified = api.request("GET", scope_path)
        if not any(str(item.get("id")) == scope_id for item in verified):
            raise RuntimeError("Keycloak did not add mcp:tools to a ChatGPT DCR client")
    return matched


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
    contextforge_client_id: str,
    contextforge_client_secret: str,
    contextforge_public_url: str,
    provider_id: str,
) -> None:
    """Create the resource and ContextForge clients."""
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
    conflicting = client_by_id(api, realm, DIRECT_RESOURCE_URL)
    if conflicting:
        api.request(
            "DELETE",
            f"/admin/realms/{urllib.parse.quote(realm)}/clients/"
            f"{urllib.parse.quote(str(conflicting['id']))}",
        )
    callback = f"{contextforge_public_url.rstrip('/')}/v1/auth/sso/callback/{provider_id}"
    ensure_client(
        api,
        realm,
        {
            "clientId": contextforge_client_id,
            "name": "ContextForge Power Wiki",
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": contextforge_client_secret,
            "standardFlowEnabled": True,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "redirectUris": [callback],
            "webOrigins": [contextforge_public_url.rstrip("/")],
            "attributes": {
                "pkce.code.challenge.method": "S256",
                "post.logout.redirect.uris": f"{contextforge_public_url.rstrip('/')}/*",
            },
        },
    )


def ensure_operator(api: JsonClient, realm: str, email: str, initial_password: str) -> None:
    """Create the non-admin OAuth operator once."""
    base = f"/admin/realms/{urllib.parse.quote(realm)}/users"
    query = urllib.parse.urlencode({"username": email, "exact": "true"})
    users = api.request("GET", f"{base}?{query}")
    existing = next((item for item in users if str(item.get("username", "")).lower() == email.lower()), None)
    if existing:
        update = dict(existing)
        update.update({"username": email, "email": email, "enabled": True, "emailVerified": True})
        api.request("PUT", f"{base}/{urllib.parse.quote(str(existing['id']))}", update)
        return
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
    realm = required_env("POWER_WIKI_KEYCLOAK_REALM", "power-wiki")
    resource_url = required_env("POWER_WIKI_RESOURCE_URL")
    validate_profile(realm, resource_url)
    provider_id = required_env("POWER_WIKI_OIDC_PROVIDER_ID", "keycloak-power-wiki")
    contextforge_public_url = required_env("CONTEXTFORGE_PUBLIC_URL", "https://kb.bamboo9527.top")
    contextforge_client_id = required_env("POWER_WIKI_OIDC_CLIENT_ID", "contextforge-power-wiki")
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
    scope_id = ensure_client_scope(api, realm, resource_url)
    ensure_realm_optional_scope(api, realm, scope_id)
    dcr_clients = ensure_chatgpt_dcr_scopes(api, realm, scope_id)
    ensure_clients(
        api,
        realm,
        resource_url,
        contextforge_client_id,
        read_secret(str(secrets_dir / "contextforge-client-secret")),
        contextforge_public_url,
        provider_id,
    )
    ensure_operator(api, realm, operator_email, read_secret(str(secrets_dir / "operator-initial-password")))
    ensure_registration_policies(api, realm, str(realm_state["id"]))
    print(
        json.dumps(
            {
                "status": "ok",
                "realm": realm,
                "resource": resource_url,
                "operator": operator_email,
                "dcr": "restricted",
                "dcr_clients_scoped": dcr_clients,
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
