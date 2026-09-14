ARG BUILD_VERSION
ARG BUILD_ARCH
FROM ghcr.io/home-assistant/base:3.24-2026.06.1

ARG BUILD_VERSION
ARG BUILD_ARCH
LABEL \
  io.hass.version="${BUILD_VERSION}" \
  io.hass.type="app" \
  io.hass.arch="${BUILD_ARCH}"

COPY rootfs /
RUN apk add --no-cache python3 \
  && chmod a+x /etc/services.d/bkho-remote-agent/run /usr/bin/bkho_remote_agent.py
