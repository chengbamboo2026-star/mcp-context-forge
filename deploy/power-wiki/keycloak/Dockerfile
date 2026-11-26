ARG KEYCLOAK_BASE_IMAGE=quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3

FROM ${KEYCLOAK_BASE_IMAGE} AS builder

ENV KC_DB=postgres \
    KC_FEATURES=resource-indicators \
    KC_HEALTH_ENABLED=true \
    KC_METRICS_ENABLED=false

RUN /opt/keycloak/bin/kc.sh build

FROM ${KEYCLOAK_BASE_IMAGE}

COPY --from=builder --chown=1000:0 /opt/keycloak/ /opt/keycloak/
