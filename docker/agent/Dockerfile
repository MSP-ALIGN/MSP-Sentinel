# MSP Sentinel agent: container image (1.36). Build from the repository root:
#   docker build -f docker/agent/Dockerfile -t msp-sentinel-agent:VERSION .
# Run it with docker/agent/docker-compose.yml (host network, unprivileged, read-only). See docs/guides/docker-agent.md.
#
# Security assumptions:
# - Runs as the unprivileged user sentinel-agent (uid 10001), with no Linux capabilities (the compose file drops them
#   all): scans are TCP connect scans (nmap --unprivileged), no raw sockets. Listening for NetBIOS name requests needs
#   port 137 and so stays off here; LLMNR (5355) works.
# - No update helper: the image is updated by pulling a new version (SENTINEL_AGENT_CONTAINER=docker tells the agent
#   and Sentinel), so nothing in the container ever changes its own code, and nothing runs as root.
# - Only the agent's code is copied (bin, src, lang, VERSION): no tests, config or server files.
# - Base image pinned to a PHP minor version; rebuild to pick up its security fixes.
FROM php:8.4-cli-bookworm

# nmap for scans, CA certificates for HTTPS to Sentinel; the sockets extension for the LLMNR listener.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-install sockets \
 && groupadd --system --gid 10001 sentinel-agent \
 && useradd --system --uid 10001 --gid 10001 --home-dir /var/lib/sentinel-agent --shell /usr/sbin/nologin sentinel-agent \
 && install -d -o sentinel-agent -g sentinel-agent -m 0700 /etc/sentinel-agent /var/lib/sentinel-agent

COPY --chown=root:root VERSION /opt/sentinel-agent/VERSION
COPY --chown=root:root bin/sentinel-agent.php /opt/sentinel-agent/bin/sentinel-agent.php
COPY --chown=root:root src /opt/sentinel-agent/src
COPY --chown=root:root lang /opt/sentinel-agent/lang

ENV SENTINEL_AGENT_CONTAINER=docker
USER sentinel-agent
WORKDIR /var/lib/sentinel-agent
VOLUME ["/etc/sentinel-agent", "/var/lib/sentinel-agent"]
ENTRYPOINT ["php", "/opt/sentinel-agent/bin/sentinel-agent.php"]
CMD ["run", "--config", "/etc/sentinel-agent/agent.json"]
