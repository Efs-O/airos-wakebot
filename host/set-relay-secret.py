"""Install the Forge WakeSleep relay secret into the dish's wake.conf.

Run this AFTER "Forge: Generate WakeSleep Relay Secret" in VS Code, which stores
the secret in SecretStorage and shows it once in a modal.  Both prompts are
hidden, so neither the relay secret nor the dish password is ever echoed, put on
a command line (where `ps` would show it), or written to a shell history file.

    python set-relay-secret.py <host>        the dish's management address

Rerun it any time the secret is rotated -- it replaces the existing lines rather
than appending duplicates, and wake.conf's LAST value would otherwise win.

The script runs as the SSH command and only the two DATA lines go to stdin.
That split matters: an earlier version piped the script itself to `sh` on stdin
and had the script `read` its data from the same place, so `read SECRET`
consumed the next LINE OF THE SCRIPT instead. It half-executed, wrote a line of
shell into FORGE_RELAY_URL and a 3-character RELAY_SECRET, and only then died
with "unterminated quoted string" -- a corrupt config from a command that
looked like it had merely failed. Never feed a shell its script and its input
on the same pipe.
"""
import getpass
import os
import re
import sys
import paramiko

HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DISH_HOST")
if not HOST:
    sys.exit("usage: set-relay-secret.py <dish-host>   (or set DISH_HOST)")
# No default: the receiver's address is per-site, and a wrong one fails as a
# connection refused inside the dish's poller rather than anywhere visible.
URL = os.environ.get("FORGE_RELAY_URL")
if not URL:
    sys.exit("Set FORGE_RELAY_URL to the Forge listener, "
             "e.g. http://<pc-ip>:8742/v1/sleep")
CONF = "/etc/persistent/wake.conf"

secret = getpass.getpass("Forge relay secret (from the VS Code modal): ").strip()
# newRelaySecret() is two dashless UUIDs, so exactly 64 lowercase hex chars.
# Checking the shape here turns a mistyped paste into a refusal now, rather than
# an unexplained 401 from Forge later.
if not re.fullmatch(r"[0-9a-fA-F]{64}", secret):
    sys.exit("Refusing: expected 64 hex characters, got %d character(s). "
             "Re-run \"Forge: Generate WakeSleep Relay Secret\" and copy the whole string."
             % len(secret))
secret = secret.lower()
pw = os.environ.get("LB_PASS") or getpass.getpass("airOS password for %s: " % HOST)

# Runs as the SSH command; stdin carries only the secret and the URL, one line
# each, in that order.
SCRIPT = r"""
set -e
read -r SECRET
read -r URL
umask 077
grep -v '^\(FORGE_RELAY_URL\|RELAY_SECRET\)=' CONFPATH > CONFPATH.new
printf 'FORGE_RELAY_URL=%s\n' "$URL" >> CONFPATH.new
printf 'RELAY_SECRET=%s\n' "$SECRET" >> CONFPATH.new
mv CONFPATH.new CONFPATH
chmod 600 CONFPATH
cfgmtd -w -p /etc/ >/dev/null 2>&1
# Verify by SHAPE, never by echoing the value back.
if grep -qE '^RELAY_SECRET=[0-9a-f]{64}$' CONFPATH; then
  echo "secret: stored, 64 hex OK"
else
  echo "secret: MALFORMED IN FILE"
fi
echo "url: $(sed -n 's/^FORGE_RELAY_URL=//p' CONFPATH)"
echo "perms: $(ls -l CONFPATH | awk '{print $1}')"
# Restart the poller so it re-reads wake.conf; the supervisor brings it back.
kill $(ps | grep '[l]ua /etc/persistent/wakebot.lua' | awk '{print $1}') 2>/dev/null || true
sleep 15
echo "running: $(ps | grep -c '[l]ua /etc/persistent/wakebot.lua')"
""".replace("CONFPATH", CONF)

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=os.environ.get("LB_USER", "ubnt"), password=pw,
          look_for_keys=False, allow_agent=False, timeout=15,
          banner_timeout=15, auth_timeout=15)
_in, out, err = c.exec_command(SCRIPT, timeout=120)
_in.write(secret + "\n" + URL + "\n")
_in.flush()
_in.channel.shutdown_write()
o = out.read().decode(errors="replace")
e = err.read().decode(errors="replace")
rc = out.channel.recv_exit_status()
c.close()

print(o.rstrip())
if e.strip():
    print("[stderr] " + e.rstrip())
print("[exit %d]" % rc)
if rc != 0 or "64 hex OK" not in o:
    sys.exit("FAILED -- wake.conf may be inconsistent. Check with:\n"
             "  python dish-wakebot/deploy.py --host %s" % HOST)
