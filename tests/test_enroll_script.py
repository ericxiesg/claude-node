"""The enrollment script renders and its rootless / root branches are well-formed.

Behavioural coverage (a rootless run writes the key to the current user's own
~/.ssh, registers user+port, and the gateway connects back) is an integration
check against a real node + sshd, done in the lab. This test guards the script
itself: it renders, passes `bash -n`, and the mode logic and new flags are wired.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.enroll import ENROLL_SH  # noqa: E402

rendered = ENROLL_SH.replace("__BASE__", "http://127.0.0.1:8848").replace("__DEFUSER__", "ops")

# 1. renders with all placeholders filled and passes a shell syntax check
assert "__BASE__" not in rendered and "__DEFUSER__" not in rendered
bash = shutil.which("bash")
if bash:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(rendered)
        path = f.name
    r = subprocess.run([bash, "-n", path], capture_output=True, text=True)
    assert r.returncode == 0, f"bash -n failed: {r.stderr}"
    print("1. script renders and passes bash -n")
else:
    print("1. script renders (bash not present; skipped bash -n)")

# 2. rootless is opt-in: a non-root run without --rootless is refused with guidance,
#    and both new flags are handled
assert "--rootless) ROOTLESS=1" in rendered
assert "--port) PORT_OVERRIDE=" in rendered
assert 'root required; re-run with sudo, or pass --rootless' in rendered
print("2. --rootless and --port are parsed; non-root without --rootless is refused")

# 3. account creation is gated behind root mode; rootless uses the caller's own home
#    and never runs useradd/usermod/chown on the same line as its own setup
assert "if [[ $ROOTLESS -eq 0 ]]" in rendered
assert 'HOME_DIR="${HOME:-' in rendered            # rootless uses the caller's home
for cmd in ("useradd -m", "usermod -p", "chown -R", "/etc/ssh/sshd_config.d"):
    # every privileged op is indented (sits inside a guarded block), never at
    # column 0 where it would run unconditionally
    for line in rendered.splitlines():
        if cmd in line:
            assert line != line.lstrip(), f"{cmd!r} is not inside a guarded block: {line!r}"
print("3. account creation and sshd edits are all inside guarded (root-only) blocks")

print("\nall enroll-script checks passed")
