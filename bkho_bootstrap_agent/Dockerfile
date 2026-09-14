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
RUN chmod a+x /etc/services.d/bkho-remote-proof/run
