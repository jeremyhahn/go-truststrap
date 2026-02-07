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

### Management

```bash
sudo systemctl status truststrap
sudo systemctl restart truststrap
sudo journalctl -u truststrap -f
```

## RC Init Script

For systems without systemd:

```bash
sudo cp init/truststrap.rc /etc/init.d/truststrap
sudo chmod 755 /etc/init.d/truststrap
sudo cp init/truststrap.env /etc/default/truststrap

# Enable at boot
sudo update-rc.d truststrap defaults    # Debian/Ubuntu
sudo chkconfig truststrap on            # RHEL/CentOS

# Manage
sudo /etc/init.d/truststrap start
sudo /etc/init.d/truststrap status
```

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
