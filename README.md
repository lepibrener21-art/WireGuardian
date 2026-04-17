# WireGuardian

A client-server CLI tool for managing WireGuard VPN peer configurations. The server exposes a token-authenticated HTTPS API and an admin CLI; the client CLI talks to that API from any machine to request, list, or remove peers.

No `wg` or `wg-quick` binary is required on the server — WireGuardian generates keypairs and configuration files in pure Python and stores everything in SQLite.

---

## Features

- Generate WireGuard keypairs (X25519) without the `wg` binary
- Automatic IP allocation from a configurable subnet
- Token-authenticated HTTPS API (Bearer token)
- Self-signed TLS certificate generation for development
- Admin CLI (`wg-server`) for direct server-side peer management
- Remote CLI (`wg-client`) for requesting and managing peers over HTTPS
- Downloaded config files saved with `chmod 600`
- SQLite storage — no external database required
- Separate Python virtual environments for server and client

---

## Requirements

- Python 3.8+
- `make`

No other system dependencies are needed.

---

## Installation

Clone the repository and run `make setup` to create isolated virtual environments for the server and client:

```bash
git clone https://github.com/lepibrener21-art/WireGuardian.git
cd WireGuardian
make setup
```

This creates `.venv-server/` (Flask, cryptography) and `.venv-client/` (requests) without touching your system Python. The wrapper scripts `./wg-server` and `./wg-client` at the repo root activate the correct venv automatically.

To set up only one side:

```bash
make setup-server   # server venv only
make setup-client   # client venv only
```

---

## Server Setup

### 1. Initialize

```bash
./wg-server --config /etc/wireguardian/server.conf server init --self-signed
```

This will:
- Create the SQLite database
- Generate a WireGuard keypair for the server
- Write a config file (mode `600`)
- Generate a self-signed TLS certificate (omit `--self-signed` if you bring your own)

The default config path is `~/.wireguardian/server.conf`.

### 2. Edit the config

```ini
[server]
private_key = <generated>
public_key  = <generated>
endpoint    = vpn.example.com:51820   # your server's public address + WireGuard port
wg_address  = 10.0.0.1/24
vpn_subnet  = 10.0.0.0/24

[api]
host     = 0.0.0.0
port     = 8443
tls_cert = /etc/wireguardian/server.crt
tls_key  = /etc/wireguardian/server.key

[auth]
token = your-secret-token-here        # share this with clients

[storage]
db_path = /etc/wireguardian/wireguardian.db
```

### 3. Start the server

```bash
./wg-server --config /etc/wireguardian/server.conf server start
```

The API listens on `https://0.0.0.0:8443` by default.

---

## Server Admin CLI (`wg-server`)

All commands accept `--config PATH` to point at a non-default config file.

```
wg-server [--config PATH] <command>

server init [--self-signed]   Initialize DB, generate server keypair, optional TLS cert
server start                  Start the HTTPS API server

peer list                     List all registered peers
peer add <NAME>               Create a peer, print its .conf and the [Peer] stanza for wg0.conf
peer show <ID>                Print the .conf for an existing peer
peer delete <ID> [--yes]      Delete a peer (prompts for confirmation unless --yes)
```

### Example

```bash
# Add a peer directly on the server
./wg-server peer add laptop

# Output:
# Peer 'laptop' added (ID: 1, IP: 10.0.0.2)
#
# === Client config (save as wireguard-laptop.conf) ===
# [Interface]
# PrivateKey = <key>
# Address = 10.0.0.2/32
# DNS = 1.1.1.1
#
# [Peer]
# PublicKey = <server-pubkey>
# Endpoint = vpn.example.com:51820
# AllowedIPs = 0.0.0.0/0
# PersistentKeepalive = 25
#
# === Add to your server wg0.conf ===
# [Peer]
# PublicKey = <client-pubkey>
# AllowedIPs = 10.0.0.2/32
```

---

## Client CLI (`wg-client`)

The client connects to the server's HTTPS API. Use `--insecure` to skip certificate verification when using a self-signed cert.

```
wg-client [--insecure] <command>

request <SERVER_URL> --token TOKEN --name NAME [--output PATH]
    Request a new peer and save its .conf file locally (default: wireguard-NAME.conf)

list <SERVER_URL> --token TOKEN
    List all peers registered on the server

delete <SERVER_URL> --token TOKEN --id ID [--yes]
    Delete a peer on the server
```

### Examples

```bash
SERVER=https://vpn.example.com:8443
TOKEN=your-secret-token-here

# Request a new peer config
./wg-client --insecure request $SERVER --token $TOKEN --name laptop
# Saves wireguard-laptop.conf (chmod 600)

# List all peers
./wg-client --insecure list $SERVER --token $TOKEN

# Delete a peer
./wg-client --insecure delete $SERVER --token $TOKEN --id 2
```

---

## API Reference

All endpoints require an `Authorization: Bearer <token>` header.

| Method | Path | Description | Success |
|--------|------|-------------|---------|
| `POST` | `/peers` | Create a peer — body: `{"name": "..."}` | `201` JSON with `config` field |
| `GET` | `/peers` | List all peers (no private keys) | `200` JSON array |
| `DELETE` | `/peers/<id>` | Delete a peer | `200` `{"deleted": true, "id": N}` |
| `GET` | `/peers/<id>/config` | Download peer `.conf` as a file | `200` `text/plain` |

**Error responses:**

| Status | Meaning |
|--------|---------|
| `400` | Missing or invalid request body |
| `401` | Bad or missing token |
| `404` | Peer not found |
| `409` | No available IPs in the subnet |

---

## Generated Client Config Format

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.0.0.X/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

---

## Project Structure

```
WireGuardian/
├── Makefile            — setup-server, setup-client, setup, clean targets
├── pyproject.toml      — package metadata and split extras ([server], [client])
├── wg-server           — wrapper script (activates .venv-server automatically)
├── wg-client           — wrapper script (activates .venv-client automatically)
├── server/
│   ├── config.py       — INI config loader/writer (dataclass)
│   ├── db.py           — SQLite queries
│   ├── wireguard.py    — key generation, IP allocation, config rendering, TLS cert gen
│   ├── api.py          — Flask app factory and API routes
│   └── main.py         — wg-server Click CLI entry point
└── client/
    └── main.py         — wg-client Click CLI entry point
```

---

## Security Notes

- The auth token is a simple pre-shared secret sent in the `Authorization` header over TLS. Use a long random string in production.
- Peer private keys are stored in the SQLite database. Restrict access to the database file accordingly.
- The `--self-signed` option is intended for development and testing only. Use a proper CA-signed certificate in production.
- Config files and the server key are written with mode `600`.

---

## License

See [LICENSE](LICENSE).
