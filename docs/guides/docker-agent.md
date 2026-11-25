# Run an agent in Docker

Run the on-premises agent as a container on a Linux Docker host at the client's site (for example a NAS or a small
server that already runs Docker). It does the same internal scans as the appliance agent.

## Before you start

- A **Linux** Docker host on the client's network (Docker Desktop on Windows or macOS can't share the host network).
- Docker Engine with the compose plugin (`docker compose version`).
- In Sentinel: the client's **Agents** page, with the site's **internal authorization** recorded.

## Set it up

1. In Sentinel, on the client's **Agents** page, click **Create an enrollment code** for the site. Keep the page open.
2. On the Docker host, get `docker/agent/docker-compose.yml` from the release (or the repository) into a folder of its
   own, for example `/opt/sentinel-agent`.
3. Choose the image:
   - **Published image** (default): `ghcr.io/msp-align/msp-sentinel-agent:VERSION`, when your Sentinel's maintainer
     publishes images. Check its signature if you like (see "Good to know").
   - **Build it yourself** from an unpacked release: `docker build -f docker/agent/Dockerfile -t msp-sentinel-agent:1.36.0 .`
     then put `SENTINEL_AGENT_IMAGE=msp-sentinel-agent` in a `.env` file next to the compose file.
4. Enroll once. Paste the enrollment code when it asks (it isn't shown on screen), then press Enter:

   ```sh
   SENTINEL_SERVER=https://sentinel.msp.example docker compose --profile enrol run --rm enrol
   ```

   It prints the release key fingerprint: compare it with **Administration → System**.
5. Start it: `docker compose up -d`. Within a minute the agent shows as **Online** on the client's Agents page, with a
   **Docker** badge.

## Update it

Docker agents don't update themselves. When Sentinel has a new version, the Agents page says
"Update by pulling image x.y.z". Set `SENTINEL_AGENT_VERSION=x.y.z` in `.env`, then:

```sh
docker compose pull && docker compose up -d
```

(If you build the image yourself, build the new version first.) Tools such as Watchtower or Portainer can do this for
you. **Update all agents** in Sentinel skips Docker agents and says how many need a new image.

## Good to know

- **Host network is required** for internal scans: the agent sees the LAN like a normal machine (device discovery, MAC
  addresses, LLMNR name requests). The compose file sets it.
- **`SENTINEL_SERVER` is only for enrolling.** The other commands (`up`, `pull`, `logs`) don't need it.
- **Unprivileged and read-only:** the container runs as user `sentinel-agent` (uid 10001) with every Linux capability
  dropped, a read-only file system and no way to gain privileges. Its config volume is mounted read-only; only the
  state volume is writable. No update helper and nothing as root.
- **NetBIOS name requests (UDP 137) aren't heard** in Docker (that port needs a privilege the container doesn't have).
  LLMNR requests are, so the "devices asking for names" finding still works for most networks.
- **Two volumes hold everything:** `config` (the enrollment: keep it, it identifies the agent) and `state`. To move the
  agent to another host, move both volumes. To enroll again, remove the `config` volume first.
- **Status:** `docker compose run --rm agent status` checks the connection and prints the agent's key fingerprint.
  Logs: `docker compose logs -f agent`.
- **Signed images** (when published from GitHub): `cosign verify ghcr.io/msp-align/msp-sentinel-agent:VERSION
  --certificate-identity-regexp '^https://github\.com/MSP-ALIGN/MSP-Sentinel/\.github/workflows/agent-image\.yml@refs/tags/v[0-9.]+$'
  --certificate-oidc-issuer https://token.actions.githubusercontent.com`. (For the maintainer: a newly published
  package on GitHub's registry starts private; make it public so sites can pull it.)
- **Sentinel with a private certificate authority:** copy its CA certificate into the config volume, then add `--ca`
  when enrolling:

  ```sh
  docker compose --profile enrol run --rm -v "$PWD/ca.pem:/ca-in.pem:ro" --entrypoint cp enrol /ca-in.pem /etc/sentinel-agent/ca.pem
  SENTINEL_SERVER=https://sentinel.msp.example docker compose --profile enrol run --rm enrol \
    enroll --server https://sentinel.msp.example --code-stdin --config /etc/sentinel-agent/agent.json \
    --state-dir /var/lib/sentinel-agent --ca /etc/sentinel-agent/ca.pem
  ```
- **Revoking:** when Sentinel revokes the agent, the container stops and stays stopped. Remove it with
  `docker compose down -v` (`-v` also deletes its volumes).
- Active Directory checks, engagements and everything else on the Agents page work as with the appliance agent.
