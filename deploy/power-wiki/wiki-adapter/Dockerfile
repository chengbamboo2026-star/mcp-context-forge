ARG BASE_IMAGE=hxds-llmwiki:b44df6ae-http-r1
FROM ${BASE_IMAGE}

COPY --chown=1000:10001 identity-jws.mjs /app/adapter/identity-jws.mjs
COPY --chown=1000:10001 server.mjs /app/adapter/server.mjs
