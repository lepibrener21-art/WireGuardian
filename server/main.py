import os
import sys

import click

from server.config import Config, load_config, save_config
from server import db, wireguard


def _load(config_path: str) -> Config:
    return load_config(config_path)


@click.group()
@click.option(
    "--config",
    "config_path",
    default=None,
    metavar="PATH",
    help="Path to server config file (default: ~/.wireguardian/server.conf)",
)
@click.pass_context
def cli(ctx: click.Context, config_path):
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path


# ---------------------------------------------------------------------------
# server group
# ---------------------------------------------------------------------------

@cli.group()
def server():
    """Server management commands."""


@server.command("init")
@click.option("--self-signed", is_flag=True, help="Generate a self-signed TLS certificate")
@click.pass_context
def server_init(ctx: click.Context, self_signed: bool):
    """Initialize database and generate server keypair."""
    cfg = _load(ctx.obj["config_path"])

    # Ensure DB directory exists and create tables
    os.makedirs(os.path.dirname(cfg.db_path) or ".", exist_ok=True)
    db.init_db(cfg.db_path)
    click.echo(f"Database initialized at {cfg.db_path}")

    # Generate server keypair if not already set
    if not cfg.server_private_key:
        priv, pub = wireguard.generate_keypair()
        cfg.server_private_key = priv
        cfg.server_public_key = pub
        click.echo(f"Generated server keypair.")
    else:
        click.echo("Server keypair already set, skipping key generation.")

    # Generate self-signed TLS cert if requested
    if self_signed:
        if not cfg.tls_cert or not cfg.tls_key:
            cfg_dir = os.path.dirname(cfg.config_path)
            cfg.tls_cert = os.path.join(cfg_dir, "server.crt")
            cfg.tls_key = os.path.join(cfg_dir, "server.key")

        if not os.path.exists(cfg.tls_cert) or not os.path.exists(cfg.tls_key):
            wireguard.generate_self_signed_cert(cfg.tls_cert, cfg.tls_key)
            click.echo(f"Self-signed TLS cert generated: {cfg.tls_cert}")
        else:
            click.echo("TLS cert already exists, skipping.")

    save_config(cfg)
    click.echo(f"Config saved to {cfg.config_path}")
    click.echo(f"\nServer public key: {cfg.server_public_key}")

    if not cfg.token:
        click.echo("\nWARNING: No auth token set. Edit the config and set [auth] token = <secret>")
    if not cfg.server_endpoint:
        click.echo("WARNING: server endpoint not set. Edit [server] endpoint = host:51820")
    click.echo("\nRun 'wg-server server start' when ready.")


@server.command("start")
@click.pass_context
def server_start(ctx: click.Context):
    """Start the HTTPS API server."""
    cfg = _load(ctx.obj["config_path"])

    missing = []
    if not cfg.server_public_key:
        missing.append("server public key (run 'server init')")
    if not cfg.token:
        missing.append("auth token ([auth] token)")
    if not cfg.tls_cert or not cfg.tls_key:
        missing.append("TLS cert/key ([api] tls_cert, tls_key)")
    if missing:
        raise click.ClickException("Missing config: " + ", ".join(missing))

    from server.api import create_app
    app = create_app(cfg)
    click.echo(f"Starting WireGuardian server on https://{cfg.api_host}:{cfg.api_port}")
    app.run(
        host=cfg.api_host,
        port=cfg.api_port,
        ssl_context=(cfg.tls_cert, cfg.tls_key),
        debug=False,
    )


# ---------------------------------------------------------------------------
# peer group
# ---------------------------------------------------------------------------

@cli.group()
def peer():
    """Peer management commands."""


@peer.command("list")
@click.pass_context
def peer_list(ctx: click.Context):
    """List all registered peers."""
    cfg = _load(ctx.obj["config_path"])
    peers = db.list_peers(cfg.db_path)

    if not peers:
        click.echo("No peers registered.")
        return

    header = f"{'ID':<5} {'Name':<20} {'IP Address':<16} {'Public Key':<46} {'Created At'}"
    click.echo(header)
    click.echo("-" * len(header))
    for p in peers:
        pub_short = p["public_key"][:44] + ".." if len(p["public_key"]) > 44 else p["public_key"]
        click.echo(f"{p['id']:<5} {p['name']:<20} {p['ip_address']:<16} {pub_short:<46} {p['created_at']}")


@peer.command("add")
@click.argument("name")
@click.pass_context
def peer_add(ctx: click.Context, name: str):
    """Add a new peer and print its WireGuard config."""
    cfg = _load(ctx.obj["config_path"])

    if not cfg.server_public_key:
        raise click.ClickException("Server public key not set. Run 'server init' first.")

    priv, pub = wireguard.generate_keypair()
    used = db.ip_addresses_in_use(cfg.db_path)

    try:
        ip = wireguard.allocate_ip(cfg.vpn_subnet, used)
    except RuntimeError as e:
        raise click.ClickException(str(e))

    peer_id = db.add_peer(cfg.db_path, name, priv, pub, ip)
    click.echo(f"Peer '{name}' added (ID: {peer_id}, IP: {ip})\n")

    conf_text = wireguard.render_client_config(
        priv, ip, cfg.server_public_key, cfg.server_endpoint or "<server-endpoint:51820>"
    )
    click.echo("=== Client config (save as wireguard-<name>.conf) ===")
    click.echo(conf_text)

    stanza = wireguard.render_server_peer_stanza(pub, ip)
    click.echo("=== Add to your server wg0.conf ===")
    click.echo(stanza)


@peer.command("show")
@click.argument("peer_id", type=int)
@click.pass_context
def peer_show(ctx: click.Context, peer_id: int):
    """Show the WireGuard config for an existing peer."""
    cfg = _load(ctx.obj["config_path"])
    p = db.get_peer(cfg.db_path, peer_id)
    if not p:
        raise click.ClickException(f"Peer {peer_id} not found.")

    conf_text = wireguard.render_client_config(
        p["private_key"],
        p["ip_address"],
        cfg.server_public_key,
        cfg.server_endpoint or "<server-endpoint:51820>",
    )
    click.echo(f"=== Config for peer '{p['name']}' (ID: {p['id']}, IP: {p['ip_address']}) ===")
    click.echo(conf_text)


@peer.command("delete")
@click.argument("peer_id", type=int)
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def peer_delete(ctx: click.Context, peer_id: int, yes: bool):
    """Delete a peer by ID."""
    cfg = _load(ctx.obj["config_path"])
    p = db.get_peer(cfg.db_path, peer_id)
    if not p:
        raise click.ClickException(f"Peer {peer_id} not found.")

    if not yes:
        click.confirm(f"Delete peer '{p['name']}' (ID: {peer_id}, IP: {p['ip_address']})?", abort=True)

    db.delete_peer(cfg.db_path, peer_id)
    click.echo(f"Peer {peer_id} deleted.")
