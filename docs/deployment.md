# Deployment Guide

## systemd Service

### Installation

```bash
# Copy binary
sudo cp bin/truststrap /usr/local/bin/
sudo chmod 755 /usr/local/bin/truststrap

# Create service user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin truststrap

# Create configuration directory
sudo mkdir -p /etc/truststrap
sudo cp your-ca-bundle.pem /etc/truststrap/ca-bundle.pem

# Copy environment file
sudo cp init/truststrap.env /etc/truststrap/truststrap.env
sudo chmod 600 /etc/truststrap/truststrap.env

# Install systemd unit
sudo cp init/truststrap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now truststrap
```

### Configuration

Edit `/etc/truststrap/truststrap.env`:

```sh
TRUSTSTRAP_BUNDLE_FILE=/etc/truststrap/ca-bundle.pem
TRUSTSTRAP_KEY_FILE=/etc/truststrap/noise.key
TRUSTSTRAP_LISTEN=:8445
TRUSTSTRAP_MAX_CONNECTIONS=100
TRUSTSTRAP_LOG_FORMAT=text
```

These are shell variables the unit expands into flags on the `ExecStart` line;
they are not read by the process. The listen address is also configurable
directly, without the unit file, through `/etc/truststrap/truststrap.yaml`
(`serve.listen`) or the `TRUSTSTRAP_SERVE_LISTEN` environment variable --
see [cli.md](cli.md#configuration-sources) for the precedence. Note that
`--listen=${TRUSTSTRAP_LISTEN}` on the `ExecStart` line is an explicitly given
flag and therefore outranks both.

### Management

```bash
sudo systemctl status truststrap
sudo systemctl restart truststrap
sudo journalctl -u truststrap -f
```

## Hosts without systemd

The repository ships no init script: it carries no shell scripts (#75), and the
SysV script it once shipped was one. `truststrap serve` needs no wrapper to run
as a service -- it stays in the foreground, logs to standard error, and shuts
down cleanly on `SIGTERM` -- so run it under whatever supervisor the host
already has (OpenRC's `supervise-daemon`, runit, s6, daemontools), as the
`truststrap` user, with the same flags the systemd unit's `ExecStart` line
passes. Instead of flags, the supervisor can export the `TRUSTSTRAP_SERVE_*`
variables or point at `/etc/truststrap/truststrap.yaml`; see
[cli.md](cli.md#configuration-sources) for the precedence.

## Docker

### Build

```bash
docker build -t truststrap:latest .
```

### Run

```bash
docker run -d \
  -v /path/to/ca-bundle.pem:/etc/truststrap/ca-bundle.pem:ro \
  -p 8445:8445 \
  truststrap:latest \
  serve --bundle-file /etc/truststrap/ca-bundle.pem --listen :8445
```

### Docker Compose

```yaml
services:
  truststrap:
    build: .
    ports:
      - "8445:8445"
    volumes:
      - ./ca-bundle.pem:/etc/truststrap/ca-bundle.pem:ro
    command: serve --bundle-file /etc/truststrap/ca-bundle.pem --listen :8445
    restart: unless-stopped
```

## Logging

### JSON format for log aggregation

```bash
truststrap serve --bundle-file ca-bundle.pem --log-format json
```

JSON output integrates with ELK, Datadog, Splunk, and other log aggregation pipelines.

### journald integration

When running as a systemd service, logs go to journald:

```bash
# Follow logs
journalctl -u truststrap -f

# Filter by severity
journalctl -u truststrap -p err

# JSON output from journald
journalctl -u truststrap -o json
```

## Security Hardening

- Run as a dedicated non-root user (`truststrap`)
- The systemd unit includes: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `MemoryDenyWriteExecute`
- Key file permissions: `0600` (owner read/write only)
- Bundle file permissions: `0644` (world readable)
- Restrict network access with firewall rules to only allow bootstrap clients
- Rotate the Noise static key periodically and redistribute the public key
