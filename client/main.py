import os
import sys

import click
import requests
from requests.exceptions import ConnectionError, SSLError, Timeout


def _session(token: str, insecure: bool) -> requests.Session:
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    # Store insecure flag; pass verify= per-request because requests 2.3x+
    # urllib3 2.x don't reliably propagate session.verify=False on all adapters.
    s._wg_insecure = insecure  # type: ignore[attr-defined]
    return s


def _req(session: requests.Session, method: str, url: str, **kwargs):
    insecure = getattr(session, "_wg_insecure", False)
    kwargs.setdefault("verify", not insecure)
    kwargs.setdefault("timeout", 15)
    return session.request(method, url, **kwargs)


def _handle_error(resp: requests.Response) -> None:
    if resp.status_code == 401:
        raise click.ClickException("Unauthorized — check your token.")
    if resp.status_code == 404:
        raise click.ClickException("Not found.")
    if not resp.ok:
        try:
            msg = resp.json().get("error", resp.text)
        except Exception:
            msg = resp.text
        raise click.ClickException(f"Server error {resp.status_code}: {msg}")


@click.group()
@click.option("--insecure", is_flag=True, help="Skip TLS certificate verification (for self-signed certs)")
@click.pass_context
def cli(ctx: click.Context, insecure: bool):
    """WireGuardian client — manage WireGuard peers on a remote server."""
    ctx.ensure_object(dict)
    ctx.obj["insecure"] = insecure
    if insecure:
        click.echo("Warning: TLS certificate verification is disabled.", err=True)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@cli.command("request")
@click.argument("server_url")
@click.option("--token", required=True, help="Pre-shared auth token")
@click.option("--name", required=True, help="Name for this peer (e.g. laptop)")
@click.option("--output", default=None, metavar="PATH", help="Output .conf path (default: wireguard-NAME.conf)")
@click.pass_context
def request_peer(ctx: click.Context, server_url: str, token: str, name: str, output: str):
    """Request a new WireGuard peer from the server and save its config file."""
    insecure = ctx.obj["insecure"]
    output_path = output or f"wireguard-{name}.conf"

    if os.path.exists(output_path):
        click.confirm(f"'{output_path}' already exists. Overwrite?", abort=True)

    session = _session(token, insecure)
    try:
        resp = _req(session, "POST", f"{server_url}/peers", json={"name": name})
    except SSLError as e:
        raise click.ClickException(f"TLS error: {e}. Use --insecure for self-signed certs.")
    except (ConnectionError, Timeout) as e:
        raise click.ClickException(f"Connection failed: {e}")

    _handle_error(resp)
    data = resp.json()

    with open(output_path, "w") as f:
        f.write(data["config"])
    os.chmod(output_path, 0o600)

    click.echo(f"Peer created successfully.")
    click.echo(f"  ID         : {data['id']}")
    click.echo(f"  Name       : {data['name']}")
    click.echo(f"  IP address : {data['ip_address']}")
    click.echo(f"  Config saved to: {output_path}")


@cli.command("list")
@click.argument("server_url")
@click.option("--token", required=True, help="Pre-shared auth token")
@click.pass_context
def list_peers(ctx: click.Context, server_url: str, token: str):
    """List all peers registered on the server."""
    insecure = ctx.obj["insecure"]
    session = _session(token, insecure)

    try:
        resp = _req(session, "GET", f"{server_url}/peers")
    except SSLError as e:
        raise click.ClickException(f"TLS error: {e}. Use --insecure for self-signed certs.")
    except (ConnectionError, Timeout) as e:
        raise click.ClickException(f"Connection failed: {e}")

    _handle_error(resp)
    peers = resp.json()

    if not peers:
        click.echo("No peers registered.")
        return

    header = f"{'ID':<5} {'Name':<20} {'IP Address':<16} {'Public Key':<46} {'Created At'}"
    click.echo(header)
    click.echo("-" * len(header))
    for p in peers:
        pub_short = p["public_key"][:44] + ".." if len(p["public_key"]) > 44 else p["public_key"]
        click.echo(f"{p['id']:<5} {p['name']:<20} {p['ip_address']:<16} {pub_short:<46} {p['created_at']}")


@cli.command("delete")
@click.argument("server_url")
@click.option("--token", required=True, help="Pre-shared auth token")
@click.option("--id", "peer_id", required=True, type=int, help="Peer ID to delete")
@click.option("--yes", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def delete_peer(ctx: click.Context, server_url: str, token: str, peer_id: int, yes: bool):
    """Delete a peer on the server."""
    insecure = ctx.obj["insecure"]

    if not yes:
        click.confirm(f"Delete peer ID {peer_id} on {server_url}?", abort=True)

    session = _session(token, insecure)
    try:
        resp = _req(session, "DELETE", f"{server_url}/peers/{peer_id}")
    except SSLError as e:
        raise click.ClickException(f"TLS error: {e}. Use --insecure for self-signed certs.")
    except (ConnectionError, Timeout) as e:
        raise click.ClickException(f"Connection failed: {e}")

    _handle_error(resp)
    click.echo(f"Peer {peer_id} deleted.")
