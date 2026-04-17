import sqlite3

from flask import Flask, jsonify, request

from server.config import Config
from server import db, wireguard


def create_app(config: Config) -> Flask:
    app = Flask(__name__)
    app.config["WG_CONFIG"] = config

    @app.before_request
    def require_token():
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != config.token:
            return jsonify({"error": "Unauthorized"}), 401

    @app.post("/peers")
    def create_peer():
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name is required"}), 400

        priv, pub = wireguard.generate_keypair()

        try:
            used = db.ip_addresses_in_use(config.db_path)
            ip = wireguard.allocate_ip(config.vpn_subnet, used)
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 409

        try:
            peer_id = db.add_peer(config.db_path, name, priv, pub, ip)
        except sqlite3.IntegrityError:
            # Race: IP was taken between read and insert; retry once
            try:
                used = db.ip_addresses_in_use(config.db_path)
                ip = wireguard.allocate_ip(config.vpn_subnet, used)
                peer_id = db.add_peer(config.db_path, name, priv, pub, ip)
            except (RuntimeError, sqlite3.IntegrityError) as e:
                return jsonify({"error": str(e)}), 409

        peer = db.get_peer(config.db_path, peer_id)
        conf_text = wireguard.render_client_config(
            priv, ip, config.server_public_key, config.server_endpoint
        )

        return jsonify({
            "id": peer["id"],
            "name": peer["name"],
            "public_key": peer["public_key"],
            "ip_address": peer["ip_address"],
            "created_at": peer["created_at"],
            "config": conf_text,
        }), 201

    @app.get("/peers")
    def list_peers():
        peers = db.list_peers(config.db_path)
        return jsonify([
            {
                "id": p["id"],
                "name": p["name"],
                "public_key": p["public_key"],
                "ip_address": p["ip_address"],
                "created_at": p["created_at"],
            }
            for p in peers
        ])

    @app.delete("/peers/<int:peer_id>")
    def delete_peer(peer_id: int):
        deleted = db.delete_peer(config.db_path, peer_id)
        if not deleted:
            return jsonify({"error": "Peer not found"}), 404
        return jsonify({"deleted": True, "id": peer_id})

    @app.get("/peers/<int:peer_id>/config")
    def get_peer_config(peer_id: int):
        peer = db.get_peer(config.db_path, peer_id)
        if not peer:
            return jsonify({"error": "Peer not found"}), 404

        conf_text = wireguard.render_client_config(
            peer["private_key"],
            peer["ip_address"],
            config.server_public_key,
            config.server_endpoint,
        )
        return (
            conf_text,
            200,
            {
                "Content-Type": "text/plain; charset=utf-8",
                "Content-Disposition": f'attachment; filename="wireguard-{peer["name"]}.conf"',
            },
        )

    return app
