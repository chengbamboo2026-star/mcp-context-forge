"""Unit tests for the Power Wiki ContextForge bootstrap script."""

from __future__ import annotations

import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[3] / "deploy" / "power-wiki" / "bootstrap.py"
SPEC = importlib.util.spec_from_file_location("power_wiki_bootstrap", SCRIPT)
assert SPEC and SPEC.loader
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class PowerWikiBootstrapTests(unittest.TestCase):
    def test_collection_accepts_list_and_paginated_response(self):
        self.assertEqual(bootstrap.collection([{"id": "one"}], "tools"), [{"id": "one"}])
        self.assertEqual(bootstrap.collection({"tools": [{"id": "two"}]}, "tools"), [{"id": "two"}])
        self.assertEqual(bootstrap.collection({"tools": "invalid"}, "tools"), [])

    def test_entity_gateway_id_accepts_supported_serializations(self):
        self.assertEqual(bootstrap.entity_gateway_id({"gatewayId": "camel"}), "camel")
        self.assertEqual(bootstrap.entity_gateway_id({"gateway_id": "snake"}), "snake")
        self.assertEqual(bootstrap.entity_gateway_id({"mcpServerId": "legacy"}), "legacy")

    def test_gateway_payload_enables_signed_header_and_meta_identity(self):
        with patch.dict(os.environ, {"POWER_WIKI_GATEWAY_NAME": "llm_wike_power"}, clear=False):
            payload = bootstrap.build_gateway_payload("secret-token")

        self.assertEqual(payload["transport"], "STREAMABLEHTTP")
        self.assertEqual(payload["auth_type"], "bearer")
        self.assertEqual(payload["auth_token"], "secret-token")
        self.assertEqual(
            payload["identity_propagation"],
            {
                "enabled": True,
                "mode": "both",
                "headers_prefix": "X-Forwarded-User",
                "sign_claims": True,
            },
        )

    def test_server_payload_enables_exact_oauth_resource(self):
        environment = {
            "POWER_WIKI_OIDC_ISSUER": "https://auth.example.test/realms/power-wiki",
            "POWER_WIKI_RESOURCE_URL": "https://kb.example.test/servers/server-id/mcp",
        }
        with patch.dict(os.environ, environment, clear=False):
            payload = bootstrap.build_server_payload(["tool-1"], [], [], "team-1")

        self.assertEqual(payload["id"], "73c72592dd9c447d86b230930e20722d")
        self.assertTrue(payload["oauth_enabled"])
        self.assertEqual(payload["team_id"], "team-1")
        self.assertEqual(payload["visibility"], "public")
        self.assertEqual(payload["oauth_config"]["resource"], environment["POWER_WIKI_RESOURCE_URL"])
        self.assertEqual(payload["oauth_config"]["authorization_servers"], [environment["POWER_WIKI_OIDC_ISSUER"]])

    def test_provider_disables_jit_and_binds_exact_audience(self):
        environment = {
            "POWER_WIKI_OIDC_ISSUER": "https://auth.example.test/realms/power-wiki",
            "POWER_WIKI_RESOURCE_URL": "https://kb.example.test/servers/server-id/mcp",
        }
        with patch.dict(os.environ, environment, clear=False):
            payload = bootstrap.build_provider_payload("client-secret")

        self.assertFalse(payload["auto_create_users"])
        self.assertTrue(payload["trusted_for_api_auth"])
        self.assertEqual(payload["api_audience"], environment["POWER_WIKI_RESOURCE_URL"])
        self.assertEqual(payload["client_secret"], "client-secret")

    def test_operator_role_has_only_data_plane_permissions(self):
        payload = bootstrap.build_operator_role_payload()

        self.assertEqual(payload["scope"], "team")
        self.assertEqual(payload["permissions"], ["servers.use", "tools.read", "tools.execute"])


if __name__ == "__main__":
    unittest.main()
