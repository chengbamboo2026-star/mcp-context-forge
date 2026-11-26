# Power Wiki deployment profiles

This directory contains two independent access profiles. Do not combine their resource audiences, Keycloak realms, Nginx routes, or release checks.

## ContextForge external MCP

This is the GPT-facing production profile.

- MCP resource: `https://kb.bamboo9527.top/servers/73c72592dd9c447d86b230930e20722d/mcp`
- Keycloak realm: `power-wiki`
- Runtime: `compose.yaml`, `bootstrap.py`, `with-secrets.sh`
- OAuth: `auth-compose.yaml`, `keycloak-bootstrap-contextforge.py`, `nginx-auth.conf`
- Public route: `nginx-kb-contextforge.conf`
- Black-box verifier: `verify-oauth.py`
- Private plugin source: `plugin/power-wiki-mcp/`
- Environment template: `contextforge.env.example`

The public virtual server must remain public only so RFC 9728 metadata is discoverable. ContextForge still requires a trusted exact-audience token, a provisioned non-admin user, dedicated-team membership, and the `power_wiki_operator` role with only `servers.use`, `tools.read`, and `tools.execute`.

## T621 direct development chain

This profile develops a direct LLM Wiki adapter. It is not the GPT-facing production route.

- MCP resource: `https://kb.bamboo9527.top/mcp`
- Keycloak realm: `power-wiki-direct-dev`
- Runtime: `power-wiki-compose.yaml`, `wiki-adapter/Dockerfile.direct`, `wiki-adapter/direct-server.mjs`
- Container: `power-llmwiki-direct-dev` on loopback port `8054`; it must not replace the ContextForge upstream container `power-llmwiki` on `app_net`
- OAuth keys: the development container joins only the dedicated Keycloak network for its internal JWKS read; the direct realm is not published as the GPT-facing authorization server
- OAuth verifier: `wiki-adapter/oauth-jwt.mjs`
- Keycloak bootstrap: `keycloak-bootstrap-direct.py`
- Public route candidate: `nginx-kb-direct-dev.conf` (development-only; not installed on the GPT-facing vhost)
- Black-box verifier: `verify-direct-oauth.py`
- Development plugin source: `plugin/power-llmwiki/`
- Environment template: `power-wiki.env.example`

Do not point the direct profile at the `power-wiki` realm. Its static audience mapper would replace the external ContextForge audience and invalidate the production GPT route.
