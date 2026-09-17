"""Process configuration. All values come from the environment (systemd EnvironmentFile)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SCOPES = ("fleet.read", "fleet.exec", "fleet.write", "fleet.admin")


def _s(name: str, default: str | None = None, *, required: bool = False) -> str:
    v = os.environ.get(name, default)
    if required and not v:
        raise RuntimeError(f"missing required environment variable {name}")
    return v or ""


def _i(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


def _b(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


def _csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in _s(name, default).split(",") if x.strip())


@dataclass(frozen=True)
class Settings:
    # Public identity
    public_url: str          # https://mcp.example.com (no trailing slash, no path)
    mcp_path: str            # /mcp
    bind_host: str
    bind_port: int

    # Storage
    data_dir: Path
    inventory_path: Path
    audit_path: Path

    # SSH
    ssh_key_path: Path
    ssh_key_passphrase: str | None
    known_hosts_path: Path | None
    strict_host_keys: bool
    connect_timeout: int
    idle_conn_ttl: int
    default_timeout: int
    max_timeout: int
    max_output_bytes: int
    max_fanout: int
    max_file_bytes: int

    # OAuth
    admin_user: str
    admin_password_hash: str
    access_ttl: int
    refresh_ttl: int
    code_ttl: int
    login_session_ttl: int
    allowed_redirect_prefixes: tuple[str, ...]
    enable_dcr: bool
    enable_cimd: bool

    # Node enrollment
    enroll_mode: str                       # open / approve / off
    enroll_key: str                        # if set, installer must pass -k
    enroll_allow_cidrs: tuple[str, ...]    # empty = any source
    enroll_user: str
    enroll_scopes: tuple[str, ...]

    # Policy
    enable_guardrails: bool
    read_only: bool

    @property
    def issuer(self) -> str:
        return self.public_url

    @property
    def resource_url(self) -> str:
        """RFC 8707 canonical URI. Must match the URL entered in Claude byte for byte."""
        return f"{self.public_url.rstrip('/')}{self.mcp_path}"

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(_s("VPSMCP_DATA_DIR", "/var/lib/vpsmcp"))
        public_url = _s("VPSMCP_PUBLIC_URL", required=True).rstrip("/")
        if not public_url.startswith("https://") and "localhost" not in public_url:
            raise RuntimeError("VPSMCP_PUBLIC_URL must be https (required by OAuth 2.1)")
        kh = _s("VPSMCP_KNOWN_HOSTS", str(data_dir / "known_hosts"))
        return cls(
            public_url=public_url,
            mcp_path="/" + _s("VPSMCP_MCP_PATH", "/mcp").strip("/"),
            bind_host=_s("VPSMCP_BIND_HOST", "127.0.0.1"),
            bind_port=_i("VPSMCP_BIND_PORT", 8848),
            data_dir=data_dir,
            inventory_path=Path(_s("VPSMCP_INVENTORY", "/etc/vpsmcp/hosts.yaml")),
            audit_path=Path(_s("VPSMCP_AUDIT_LOG", str(data_dir / "audit.jsonl"))),
            ssh_key_path=Path(_s("VPSMCP_SSH_KEY", "/etc/vpsmcp/id_ed25519")),
            ssh_key_passphrase=os.environ.get("VPSMCP_SSH_KEY_PASSPHRASE") or None,
            known_hosts_path=Path(kh) if kh else None,
            strict_host_keys=_b("VPSMCP_STRICT_HOST_KEYS", True),
            connect_timeout=_i("VPSMCP_CONNECT_TIMEOUT", 15),
            idle_conn_ttl=_i("VPSMCP_IDLE_CONN_TTL", 600),
            default_timeout=_i("VPSMCP_DEFAULT_TIMEOUT", 60),
            max_timeout=_i("VPSMCP_MAX_TIMEOUT", 900),
            max_output_bytes=_i("VPSMCP_MAX_OUTPUT_BYTES", 32_000),
            max_fanout=_i("VPSMCP_MAX_FANOUT", 8),
            max_file_bytes=_i("VPSMCP_MAX_FILE_BYTES", 4_000_000),
            admin_user=_s("VPSMCP_ADMIN_USER", "admin"),
            admin_password_hash=_s("VPSMCP_ADMIN_PASSWORD_HASH", required=True),
            access_ttl=_i("VPSMCP_ACCESS_TTL", 900),
            refresh_ttl=_i("VPSMCP_REFRESH_TTL", 30 * 86400),
            code_ttl=_i("VPSMCP_CODE_TTL", 120),
            login_session_ttl=_i("VPSMCP_LOGIN_SESSION_TTL", 3600),
            allowed_redirect_prefixes=_csv(
                "VPSMCP_ALLOWED_REDIRECTS",
                "https://claude.ai/api/mcp/auth_callback,"
                "https://claude.com/api/mcp/auth_callback,"
                "http://localhost/callback,http://127.0.0.1/callback",
            ),
            enable_dcr=_b("VPSMCP_ENABLE_DCR", True),
            enable_cimd=_b("VPSMCP_ENABLE_CIMD", True),
            enroll_mode=_s("VPSMCP_ENROLL_MODE", "open").lower(),
            enroll_key=_s("VPSMCP_ENROLL_KEY", ""),
            enroll_allow_cidrs=_csv("VPSMCP_ENROLL_ALLOW_CIDRS", ""),
            enroll_user=_s("VPSMCP_ENROLL_USER", "ops"),
            enroll_scopes=_csv("VPSMCP_ENROLL_SCOPES",
                               "fleet.read,fleet.exec,fleet.write"),
            enable_guardrails=_b("VPSMCP_ENABLE_GUARDRAILS", True),
            read_only=_b("VPSMCP_READ_ONLY", False),
        )
