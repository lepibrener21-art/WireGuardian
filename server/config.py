import configparser
import os
from dataclasses import dataclass, field
from typing import Optional


DEFAULT_CONFIG_PATH = os.path.expanduser("~/.wireguardian/server.conf")


@dataclass
class Config:
    server_private_key: str = ""
    server_public_key: str = ""
    server_endpoint: str = ""
    server_wg_address: str = "10.0.0.1/24"
    vpn_subnet: str = "10.0.0.0/24"
    api_host: str = "0.0.0.0"
    api_port: int = 8443
    tls_cert: str = ""
    tls_key: str = ""
    token: str = ""
    db_path: str = os.path.expanduser("~/.wireguardian/wireguardian.db")
    config_path: str = field(default=DEFAULT_CONFIG_PATH, repr=False)


def load_config(path: Optional[str] = None) -> Config:
    config_path = path or os.environ.get("WIREGUARDIAN_CONFIG", DEFAULT_CONFIG_PATH)
    config_path = os.path.expanduser(config_path)

    parser = configparser.ConfigParser()
    parser.read(config_path)

    cfg = Config(config_path=config_path)

    if parser.has_section("server"):
        s = parser["server"]
        cfg.server_private_key = s.get("private_key", cfg.server_private_key)
        cfg.server_public_key = s.get("public_key", cfg.server_public_key)
        cfg.server_endpoint = s.get("endpoint", cfg.server_endpoint)
        cfg.server_wg_address = s.get("wg_address", cfg.server_wg_address)
        cfg.vpn_subnet = s.get("vpn_subnet", cfg.vpn_subnet)

    if parser.has_section("api"):
        a = parser["api"]
        cfg.api_host = a.get("host", cfg.api_host)
        cfg.api_port = int(a.get("port", str(cfg.api_port)))
        cfg.tls_cert = a.get("tls_cert", cfg.tls_cert)
        cfg.tls_key = a.get("tls_key", cfg.tls_key)

    if parser.has_section("auth"):
        cfg.token = parser["auth"].get("token", cfg.token)

    if parser.has_section("storage"):
        cfg.db_path = os.path.expanduser(
            parser["storage"].get("db_path", cfg.db_path)
        )

    # Environment variable overrides
    cfg.server_private_key = os.environ.get("WG_PRIVATE_KEY", cfg.server_private_key)
    cfg.server_public_key = os.environ.get("WG_PUBLIC_KEY", cfg.server_public_key)
    cfg.token = os.environ.get("WG_TOKEN", cfg.token)

    return cfg


def save_config(cfg: Config) -> None:
    os.makedirs(os.path.dirname(cfg.config_path), exist_ok=True)

    parser = configparser.ConfigParser()
    parser["server"] = {
        "private_key": cfg.server_private_key,
        "public_key": cfg.server_public_key,
        "endpoint": cfg.server_endpoint,
        "wg_address": cfg.server_wg_address,
        "vpn_subnet": cfg.vpn_subnet,
    }
    parser["api"] = {
        "host": cfg.api_host,
        "port": str(cfg.api_port),
        "tls_cert": cfg.tls_cert,
        "tls_key": cfg.tls_key,
    }
    parser["auth"] = {"token": cfg.token}
    parser["storage"] = {"db_path": cfg.db_path}

    with open(cfg.config_path, "w") as f:
        parser.write(f)

    os.chmod(cfg.config_path, 0o600)
