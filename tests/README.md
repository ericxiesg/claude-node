# End-to-end tests

Not unit tests: these run real SSH against a real sshd.

## Setup

```bash
# 1) local test sshd on port 2222
sudo apt-get install -y openssh-server
D=$(mktemp -d); mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f $D/host_ed25519
ssh-keygen -q -t ed25519 -N '' -f $D/client_key
mkdir -p ~/.ssh && cat $D/client_key.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
cat > $D/sshd_config <<CFG
Port 2222
ListenAddress 127.0.0.1
HostKey $D/host_ed25519
PidFile $D/sshd.pid
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
AuthorizedKeysFile $HOME/.ssh/authorized_keys
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM no
StrictModes no
CFG
/usr/sbin/sshd -f $D/sshd_config
ssh-keyscan -p 2222 -t ed25519 127.0.0.1 > $D/known_hosts 2>/dev/null

# 2) inventory
cat > $D/hosts.yaml <<YAML
defaults: {user: root, port: 2222}
hosts:
  - alias: lab-1
    address: 127.0.0.1
    tags: [lab, local]
    scopes: [fleet.read, fleet.exec, fleet.write, fleet.admin]
    workdir: /tmp
YAML

# 3) environment
export PYTHONPATH=$PWD/src
export VPSMCP_PUBLIC_URL=http://localhost:8848
export VPSMCP_DATA_DIR=$D/data VPSMCP_INVENTORY=$D/hosts.yaml
export VPSMCP_SSH_KEY=$D/client_key VPSMCP_KNOWN_HOSTS=$D/known_hosts
export VPSMCP_ADMIN_USER=eric
export VPSMCP_ADMIN_PASSWORD_HASH=$(python3 -c "
import sys; sys.path.insert(0,'src')
from vpsmcp.auth.keys import hash_password; print(hash_password('correct-horse-battery'))")

# 4) start
python3 -m vpsmcp serve &
```

## Run

```bash
python3 tests/test_oauth_flow.py  $D/token.json   # 14 OAuth assertions
python3 tests/test_tools_e2e.py   $D/token.json   # all tools
python3 tests/test_scopes.py                      # scope isolation, token forgery
python3 tests/test_gateway_node.py $TOKEN_FILE    # on a real gateway installed with --self-enroll (host alias gw)
```

The password `correct-horse-battery` is hardcoded for local testing only.

`test_gateway_node.py` does not use the lab above: it needs a real gateway
installed with `--self-enroll` (the gateway appears as host `gw`) and a token
file obtained against it.

## Covered

- DCR registration, redirect_uri allowlist, login lockout
- PKCE, single-use codes, replay revocation, refresh rotation and reuse
  detection, audience binding
- 401 with `WWW-Authenticate`, tampered signature, forged audience and algorithm
- Scope isolation: a read-only token reaches no exec/write/admin tool
- exec exit codes, timeout really killing the process, output truncation,
  guardrail refusal and `confirm=true` pass-through
- Persistent shell keeping cwd and variables; chunked file read/write with
  automatic backup; refusal to delete dangerous paths
- Jobs running, finishing and being killed; incremental output with no gaps or
  duplicates
- Log subscription cursors; tunnel plus HTTP through it
- Gateway as a node: works normally, and six privilege probes (private key,
  inventory, password hash, oauth.db, audit log, venv) are all denied

Not automated (verify by hand before a release): migration export → wipe →
import keeping refresh tokens valid, uninstall stripping only the gateway key
from nodes, and `gen-caddyfile.sh` output passing `caddy validate`.
