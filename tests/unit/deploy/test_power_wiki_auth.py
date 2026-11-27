"""Unit tests for the Power Wiki OAuth deployment helpers."""

from __future__ import annotations

import importlib.util
import ipaddress
import unittest
import unittest.mock
from pathlib import Path


ROOT = Path(__file__).parents[3] / "deploy" / "power-wiki"


def load_script(name: str, filename: str):
    """Load one deployment script as a Python module."""
    specification = importlib.util.spec_from_file_location(name, ROOT / filename)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


keycloak = load_script("power_wiki_keycloak_bootstrap_direct", "keycloak-bootstrap-direct.py")
contextforge_keycloak = load_script(
    "power_wiki_keycloak_bootstrap_contextforge",
    "keycloak-bootstrap-contextforge.py",
)
allowlist = load_script("power_wiki_openai_allowlist", "render-openai-allowlist.py")
oauth_verifier = load_script("power_wiki_oauth_verifier", "verify-oauth.py")


class PowerWikiKeycloakTests(unittest.TestCase):
    def test_profiles_reject_cross_chain_reconciliation(self):
        with self.assertRaisesRegex(RuntimeError, "Direct profile"):
            keycloak.validate_profile(
                "power-wiki",
                "https://kb.bamboo9527.top/servers/73c72592dd9c447d86b230930e20722d/mcp",
            )
        with self.assertRaisesRegex(RuntimeError, "ContextForge profile"):
            contextforge_keycloak.validate_profile(
                "power-wiki-direct-dev",
                "https://kb.bamboo9527.top/mcp",
            )

        keycloak.validate_profile("power-wiki-direct-dev", "https://kb.bamboo9527.top/mcp")
        contextforge_keycloak.validate_profile(
            "power-wiki",
            "https://kb.bamboo9527.top/servers/73c72592dd9c447d86b230930e20722d/mcp",
        )

    def test_realm_disables_self_registration_and_rotates_refresh_tokens(self):
        payload = keycloak.realm_payload("power-wiki")

        self.assertFalse(payload["registrationAllowed"])
        self.assertTrue(payload["bruteForceProtected"])
        self.assertTrue(payload["revokeRefreshToken"])
        self.assertEqual(payload["refreshTokenMaxReuse"], 0)

    def test_audience_mapper_uses_exact_resource(self):
        resource = "https://kb.example.test/mcp"
        mapper = keycloak.audience_mapper(resource)

        self.assertEqual(mapper["protocolMapper"], "oidc-audience-mapper")
        self.assertEqual(mapper["config"]["included.client.audience"], resource)
        self.assertEqual(mapper["config"]["access.token.claim"], "true")

    def test_existing_client_scope_mapper_is_updated_and_read_back(self):
        resource = "https://kb.bamboo9527.top/mcp"
        mapper = {"id": "mapper-id", **keycloak.audience_mapper("https://kb.bamboo9527.top/old")}
        calls = []

        class Api:
            def request(self, method, path, data=None, **_kwargs):
                calls.append((method, path, data))
                if path.endswith("/client-scopes"):
                    return [{"id": "scope-id", "name": "mcp:tools"}]
                if method == "PUT" and path.endswith("/mapper-id"):
                    mapper.update(data)
                    return None
                if "/protocol-mappers/models" in path:
                    return [mapper]
                return None

        keycloak.ensure_client_scope(Api(), "power-wiki-direct-dev", resource)

        self.assertTrue(any(method == "PUT" and path.endswith("/mapper-id") for method, path, _ in calls))
        self.assertEqual(mapper["config"]["included.client.audience"], resource)

    def test_realm_optional_scope_is_added_and_verified(self):
        calls = []
        responses = [[], [{"id": "scope-id", "name": "mcp:tools"}]]

        class Api:
            def request(self, method, path, data=None, **_kwargs):
                calls.append((method, path, data))
                if method == "GET":
                    return responses.pop(0)
                return None

        contextforge_keycloak.ensure_realm_optional_scope(Api(), "power-wiki", "scope-id")

        self.assertIn(
            (
                "PUT",
                "/admin/realms/power-wiki/default-optional-client-scopes/scope-id",
                None,
            ),
            calls,
        )

    def test_existing_chatgpt_dcr_clients_receive_mcp_scope(self):
        calls = []
        clients = [
            {
                "id": "chatgpt-client",
                "protocol": "openid-connect",
                "publicClient": True,
                "standardFlowEnabled": True,
                "redirectUris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
            },
            {
                "id": "unrelated-client",
                "protocol": "openid-connect",
                "publicClient": True,
                "standardFlowEnabled": True,
                "redirectUris": ["https://example.test/callback"],
            },
        ]
        scope_reads = [[], [{"id": "scope-id", "name": "mcp:tools"}]]

        class Api:
            def request(self, method, path, data=None, **_kwargs):
                calls.append((method, path, data))
                if path.endswith("/clients?max=1000"):
                    return clients
                if method == "GET" and path.endswith("/optional-client-scopes"):
                    return scope_reads.pop(0)
                return None

        matched = contextforge_keycloak.ensure_chatgpt_dcr_scopes(Api(), "power-wiki", "scope-id")

        self.assertEqual(matched, 1)
        self.assertIn(
            (
                "PUT",
                "/admin/realms/power-wiki/clients/chatgpt-client/optional-client-scopes/scope-id",
                None,
            ),
            calls,
        )
        self.assertFalse(any("unrelated-client/optional-client-scopes" in path for _, path, _ in calls))

    def test_codex_callback_is_bound_to_the_complete_resource_url(self):
        resource = "https://kb.bamboo9527.top/servers/73c72592dd9c447d86b230930e20722d/mcp"

        callback = contextforge_keycloak.codex_callback_url(resource, 12798)

        self.assertEqual(callback, "http://127.0.0.1:12798/callback/MMQ4xFY2-pUR")
        self.assertNotEqual(
            callback,
            contextforge_keycloak.codex_callback_url(f"{resource}?tenant=other", 12798),
        )

    def test_codex_callback_rejects_an_invalid_port(self):
        with self.assertRaisesRegex(RuntimeError, "between 1 and 65535"):
            contextforge_keycloak.codex_callback_url("https://kb.example.test/mcp", 0)

    def test_contextforge_profile_creates_public_codex_client(self):
        calls = []
        scope_reads = [[], [{"id": "scope-id", "name": "mcp:tools"}]]

        class Api:
            def request(self, method, path, data=None, **_kwargs):
                calls.append((method, path, data))
                if method == "GET" and path.endswith("/optional-client-scopes"):
                    return scope_reads.pop(0)
                if method == "GET" and path.endswith("/clients/codex-internal-id"):
                    return {
                        "clientId": "power-wiki-codex",
                        "publicClient": True,
                        "standardFlowEnabled": True,
                        "directAccessGrantsEnabled": False,
                        "redirectUris": ["http://127.0.0.1:12798/callback/MMQ4xFY2-pUR"],
                        "attributes": {"pkce.code.challenge.method": "S256"},
                    }
                return None

        with unittest.mock.patch.object(
            contextforge_keycloak,
            "ensure_client",
            return_value="codex-internal-id",
        ) as ensure_client:
            callback = contextforge_keycloak.ensure_codex_client(
                Api(),
                "power-wiki",
                "https://kb.bamboo9527.top/servers/73c72592dd9c447d86b230930e20722d/mcp",
                "scope-id",
                "power-wiki-codex",
                12798,
            )

        payload = ensure_client.call_args.args[2]
        self.assertEqual(callback, "http://127.0.0.1:12798/callback/MMQ4xFY2-pUR")
        self.assertTrue(payload["publicClient"])
        self.assertTrue(payload["standardFlowEnabled"])
        self.assertFalse(payload["directAccessGrantsEnabled"])
        self.assertFalse(payload["fullScopeAllowed"])
        self.assertNotIn("secret", payload)
        self.assertEqual(payload["attributes"]["pkce.code.challenge.method"], "S256")
        self.assertIn(
            (
                "PUT",
                "/admin/realms/power-wiki/clients/codex-internal-id/optional-client-scopes/scope-id",
                None,
            ),
            calls,
        )

    def test_chatgpt_dcr_client_rejects_untrusted_redirect(self):
        client = {
            "protocol": "openid-connect",
            "publicClient": True,
            "standardFlowEnabled": True,
            "redirectUris": ["https://evil.example/connector_platform_oauth_redirect"],
        }

        self.assertFalse(contextforge_keycloak.is_chatgpt_dcr_client(client))

    def test_resource_client_is_bearer_only(self):
        calls = []

        class Api:
            def request(self, method, path, data=None, **_kwargs):
                calls.append((method, path, data))
                if method == "GET":
                    return []
                return None

        with unittest.mock.patch.object(
            keycloak,
            "client_by_id",
            side_effect=[None, {"id": "resource-id"}, None],
        ):
            keycloak.ensure_clients(Api(), "power-wiki", "https://kb.example.test/mcp")

        payload = next(data for method, path, data in calls if method == "POST" and path.endswith("/clients"))
        self.assertTrue(payload["bearerOnly"])
        self.assertFalse(payload["standardFlowEnabled"])
        self.assertNotIn("secret", payload)

    def test_contextforge_profile_creates_confidential_callback_client(self):
        calls = []

        class Api:
            def request(self, method, path, data=None, **_kwargs):
                calls.append((method, path, data))
                return None

        with (
            unittest.mock.patch.object(contextforge_keycloak, "ensure_client") as ensure_client,
            unittest.mock.patch.object(contextforge_keycloak, "client_by_id", return_value=None),
        ):
            contextforge_keycloak.ensure_clients(
                Api(),
                "power-wiki",
                "https://kb.example.test/servers/server-id/mcp",
                "contextforge-power-wiki",
                "client-secret",
                "https://kb.example.test",
                "keycloak-power-wiki",
            )

        resource_payload, browser_payload = [call.args[2] for call in ensure_client.call_args_list]
        self.assertTrue(resource_payload["bearerOnly"])
        self.assertFalse(browser_payload["publicClient"])
        self.assertTrue(browser_payload["standardFlowEnabled"])
        self.assertEqual(
            browser_payload["redirectUris"],
            ["https://kb.example.test/v1/auth/sso/callback/keycloak-power-wiki"],
        )
        self.assertEqual(browser_payload["attributes"]["pkce.code.challenge.method"], "S256")

    def test_contextforge_admin_honors_rate_limit_retry(self):
        admin = oauth_verifier.ContextForgeAdmin.__new__(oauth_verifier.ContextForgeAdmin)
        admin.base_url = "https://contextforge.example.test"
        admin.token = "test-token"
        responses = [
            oauth_verifier.HttpError(429, "GET /v1/teams", retry_after=2),
            ({"teams": []}, {}),
        ]

        with (
            unittest.mock.patch.object(oauth_verifier, "http_json", side_effect=responses),
            unittest.mock.patch.object(oauth_verifier.time, "sleep") as sleep,
        ):
            result = admin.request("GET", "/v1/teams")

        self.assertEqual(result, {"teams": []})
        sleep.assert_called_once_with(2)

    def test_keycloak_admin_refreshes_expired_token_once(self):
        admin = oauth_verifier.KeycloakAdmin.__new__(oauth_verifier.KeycloakAdmin)
        admin.base_url = "https://keycloak.example.test"
        admin.realm = "power-wiki"
        admin.username = "power-wiki-admin"
        admin.password = "test-password"
        admin.token = "expired-token"

        responses = [
            oauth_verifier.HttpError(401, "GET /admin/realms/power-wiki/users"),
            ({"access_token": "fresh-token"}, {}),
            ([{"id": "user-id"}], {}),
        ]
        with unittest.mock.patch.object(oauth_verifier, "http_json", side_effect=responses) as http_json:
            result = admin.request("GET", "/users")

        self.assertEqual(result, [{"id": "user-id"}])
        self.assertEqual(admin.token, "fresh-token")
        self.assertEqual(http_json.call_count, 3)
        self.assertEqual(http_json.call_args_list[-1].kwargs["token"], "fresh-token")

    def test_oauth_discovery_requires_exact_resource_and_issuer(self):
        resource = "https://kb.example.test/servers/550e8400-e29b-41d4-a716-446655440000/mcp"
        issuer = "https://auth.example.test/realms/power-wiki"
        responses = [
            (
                {
                    "resource": resource,
                    "authorization_servers": [issuer],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["openid", "mcp:tools"],
                },
                {},
            ),
            (
                {
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                    "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
                    "registration_endpoint": f"{issuer}/clients-registrations/openid-connect",
                    "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
                    "code_challenge_methods_supported": ["S256"],
                    "authorization_response_iss_parameter_supported": True,
                },
                {},
            ),
            (
                {
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                    "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
                    "registration_endpoint": f"{issuer}/clients-registrations/openid-connect",
                    "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
                    "code_challenge_methods_supported": ["S256"],
                    "authorization_response_iss_parameter_supported": True,
                },
                {},
            ),
        ]

        with unittest.mock.patch.object(oauth_verifier, "http_json", side_effect=responses) as http_json:
            result = oauth_verifier.verify_oauth_discovery(resource, issuer)

        self.assertEqual(
            result["resource_metadata"],
            "https://kb.example.test/.well-known/oauth-protected-resource/servers/550e8400-e29b-41d4-a716-446655440000/mcp",
        )
        self.assertEqual(
            result["authorization_server_metadata"],
            "https://auth.example.test/.well-known/oauth-authorization-server/realms/power-wiki",
        )
        self.assertEqual(http_json.call_count, 3)

    def test_oauth_discovery_requires_public_pkce_token_exchange(self):
        resource = "https://kb.example.test/servers/550e8400-e29b-41d4-a716-446655440000/mcp"
        issuer = "https://auth.example.test/realms/power-wiki"
        responses = [
            (
                {
                    "resource": resource,
                    "authorization_servers": [issuer],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": ["mcp:tools"],
                },
                {},
            ),
            (
                {
                    "issuer": issuer,
                    "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
                    "token_endpoint": f"{issuer}/protocol/openid-connect/token",
                    "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
                    "registration_endpoint": f"{issuer}/clients-registrations/openid-connect",
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                    "code_challenge_methods_supported": ["S256"],
                    "authorization_response_iss_parameter_supported": True,
                },
                {},
            ),
        ]

        with (
            unittest.mock.patch.object(oauth_verifier, "http_json", side_effect=responses),
            self.assertRaisesRegex(RuntimeError, "public PKCE token exchange"),
        ):
            oauth_verifier.verify_oauth_discovery(resource, issuer)

    def test_oauth_discovery_rejects_non_public_metadata_failure(self):
        resource = "https://kb.example.test/servers/550e8400-e29b-41d4-a716-446655440000/mcp"

        with (
            unittest.mock.patch.object(
                oauth_verifier,
                "http_json",
                side_effect=oauth_verifier.HttpError(404, "GET protected-resource metadata"),
            ),
            self.assertRaisesRegex(oauth_verifier.HttpError, "HTTP 404"),
        ):
            oauth_verifier.verify_oauth_discovery(resource, "https://auth.example.test/realms/power-wiki")

    def test_server_profile_requires_dedicated_team(self):
        server = {
            "id": "server-id",
            "teamId": "operator-team-id",
            "visibility": "public",
            "oauthEnabled": True,
            "oauthConfigApproved": True,
        }

        result = oauth_verifier.verify_server_profile(server, "server-id", "operator-team-id")

        self.assertEqual(result["team_id"], "operator-team-id")
        with self.assertRaisesRegex(RuntimeError, "dedicated operator team"):
            oauth_verifier.verify_server_profile(server, "server-id", "personal-team-id")


class OpenAIAllowlistTests(unittest.TestCase):
    def test_parse_and_render_public_prefixes(self):
        payload = {
            "creationTime": "2026-11-25T00:00:00Z",
            "prefixes": [{"ipv4Prefix": f"203.0.113.{value}/32"} for value in range(1, 11)],
        }

        with self.assertRaisesRegex(ValueError, "not public"):
            allowlist.parse_prefixes(payload)

        public_payload = {
            "creationTime": "2026-11-25T00:00:00Z",
            "prefixes": [{"ipv4Prefix": f"8.8.8.{value}/32"} for value in range(1, 11)],
        }
        creation_time, networks = allowlist.parse_prefixes(public_payload)
        rendered = allowlist.render_allowlist(creation_time, networks)

        self.assertEqual(len(networks), 10)
        self.assertIn("allow 127.0.0.1;", rendered)
        self.assertIn("allow 8.8.8.1/32;", rendered)
        self.assertNotIn("deny all", rendered)

    def test_parse_rejects_private_prefix(self):
        payload = {
            "creationTime": "2026-11-25T00:00:00Z",
            "prefixes": [{"ipv4Prefix": "10.0.0.0/8"}] * 10,
        }

        with self.assertRaisesRegex(ValueError, "not public"):
            allowlist.parse_prefixes(payload)

    def test_render_accepts_ipv6(self):
        rendered = allowlist.render_allowlist("now", [ipaddress.ip_network("2001:4860:4860::8888/128")])

        self.assertIn("allow 2001:4860:4860::8888/128;", rendered)


if __name__ == "__main__":
    unittest.main()
