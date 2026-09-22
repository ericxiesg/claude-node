# VPS Fleet MCP

Turn a fleet of VPS hosts into one remote MCP service for Claude, Kimi or GLM.
Pure SSH, no agent on the managed machines.

English · [中文](docs/README_ZH.md)

[Architecture](docs/ARCHITECTURE.md) ·
[Reference](docs/REFERENCE.md) ·
[Operations](docs/OPERATIONS.md) ·
[Troubleshooting](docs/TROUBLESHOOTING.md)

---

## 1. Install the gateway

Point a DNS A record at the machine first and wait for it to resolve.

```bash
git clone https://github.com/ericxiesg/claude-node.git && cd claude-node
sudo deploy/install.sh
```

Prompts for domain, admin username (defaults to your login user) and password
(empty generates one and prints it once). Everything else is automatic: system
packages, Caddy, SSH keypair, config, systemd unit, certificate, service start,
self-test.

Unattended:

```bash
sudo deploy/install.sh --domain mcp.example.com -y [--self-enroll] [--lock-anthropic]
```

## 2. Connect a client

One URL, the one the installer printed, for every client:

```
https://mcp.example.com/mcp
```

- **Claude** - Settings → Connectors → add a custom connector.
- **Kimi** - add an MCP server and paste the same URL.
- **GLM / Z.ai** - same: add an MCP server with that URL.

Each one sends you to your own sign-in page; approve there and it is connected.
Start with `fleet.read` and `fleet.exec` only.

```bash
sudo vpsmcp clients      # which clients are accepted, and where each calls back
sudo vpsmcp redirects    # callbacks that were turned away, and how to allow one
```

A client is accepted when its OAuth callback is in the allowlist. Claude, Kimi and
GLM are built in (`VPSMCP_CLIENTS=claude,local,kimi,glm`). Any other client - or a
vendor that moves its callback - is one command away:

```bash
sudo vpsmcp redirect allow https://example.ai/api/mcp/callback
```

`vpsmcp redirects` prints the exact URL that was refused, so nothing has to be
guessed; it applies immediately, with no restart. Allow only a URL you recognise:
that is where the authorization code is sent.

## 3. Add nodes

One command on the target machine. No token, the endpoint is permanent.

```bash
curl -sSf https://mcp.example.com/enroll/install.sh | sudo bash
```

Silent: no output, exit 0. The node name defaults to its hostname.

```bash
... | sudo bash -s -- --alias web-01                 # explicit name
... | sudo bash -s -- --alias web-01 --tags prod,hk  # with tags
... | sudo bash -s -- --user deploy                  # different local account
... | sudo bash -s -- -k <key>                       # if VPSMCP_ENROLL_KEY is set
... | sudo bash -s -- -v                             # verbose, for debugging
... | sudo bash -s -- --uninstall                    # detach this machine
```

The node gets a low-privilege account and the gateway's **public** key. No code,
no private keys. Re-running on the same machine updates the entry in place.

New nodes get `fleet.read,fleet.exec,fleet.write` by default
(`VPSMCP_ENROLL_SCOPES`).

Anyone who knows the URL can enroll a machine they control. Tighten with:

```ini
VPSMCP_ENROLL_MODE=open|approve|off
VPSMCP_ENROLL_KEY=<secret>
VPSMCP_ENROLL_ALLOW_CIDRS=1.2.3.0/24
```

## 4. Manage

```bash
sudo vpsmcp nodes                                  # node_id / alias / address / user
sudo vpsmcp node remove  <node_id|alias>
sudo vpsmcp node scopes  <node_id|alias> fleet.read,fleet.exec
sudo vpsmcp node rename  <node_id|alias> <new-alias>
sudo vpsmcp node tags    <node_id|alias> a,b
sudo vpsmcp check                                  # connectivity to every node
sudo deploy/healthcheck.sh                         # layered health check

sudo vpsmcp clients                                # accepted MCP clients
sudo vpsmcp redirects                              # callback allowlist + refusals
sudo vpsmcp redirect allow <uri>                   # accept one more client
sudo vpsmcp redirect deny  <uri>
sudo vpsmcp grants                                 # who holds a live token
sudo vpsmcp revoke <client_id>
```

Aliases may repeat. Identity is `node_id` (hash of address:port:user); pass it
when an alias is ambiguous.

## Upgrade

```bash
cd claude-node && git pull && sudo deploy/upgrade.sh --fast
```

Config and data are untouched: nodes stay enrolled, grants keep working.
Roll back with `sudo deploy/upgrade.sh --rollback`.

## Uninstall

```bash
# one node
sudo vpsmcp node remove web-01
curl -sSf https://mcp.example.com/enroll/install.sh | sudo bash -s -- --uninstall

# the gateway
sudo deploy/uninstall.sh
```

Order matters: the gateway strips its key from every node while it still works,
then deletes its own config.

## Notes

1. Run CLI commands as `sudo vpsmcp ...`. The wrapper switches to the service
   account, so permissions behave the same as they do for the daemon.
2. Do not change the resource URL once a client has been authorized; it is bound
   into issued tokens.
3. Command guardrails catch accidents, not attacks. The real boundary is the
   unprivileged SSH account on each node - do not give it sudo.
4. `--lock-anthropic` restricts the API endpoints to Anthropic's egress range, so
   it blocks Kimi, GLM and Claude Code. Leave it off unless Claude on the web is
   your only client (`--allow-cidr` adds networks of your own).

## License

MIT
