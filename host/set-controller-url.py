"""Set the non-secret Host Controller URL in the dish wakebot config.

This never reads or prints secret values. It replaces only CONTROLLER_URL,
commits the config, and restarts the existing supervisor-managed bot.
"""
import argparse
import getpass
import os
import paramiko

CONF = "/etc/persistent/wake.conf"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("DISH_HOST"), required=False)
    parser.add_argument("--url", default=os.environ.get("CONTROLLER_URL"))
    args = parser.parse_args()
    if not args.host:
        raise SystemExit("Pass --host or set DISH_HOST.")
    # No default: the controller's address is per-site, and a wrong one fails as
    # a connection refused inside the dish rather than anywhere visible.
    if not args.url:
        raise SystemExit("Pass --url or set CONTROLLER_URL, "
                         "e.g. http://<pc-lan-ip>:8787")
    if not args.url.startswith("http://") or any(char in args.url for char in " \t\r\n'\"`"):
        raise SystemExit("Refusing: --url must be a plain http:// LAN URL without shell characters.")

    password = os.environ.get("LB_PASS") or getpass.getpass(
        f"airOS password for {args.host}: "
    )
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        args.host,
        username=os.environ.get("LB_USER", "ubnt"),
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
        banner_timeout=15,
        auth_timeout=15,
    )
    script = f"""
set -e
umask 077
grep -v '^CONTROLLER_URL=' {CONF} > {CONF}.new
printf 'CONTROLLER_URL=%s\\n' '{args.url}' >> {CONF}.new
mv {CONF}.new {CONF}
chmod 600 {CONF}
cfgmtd -w -p /etc/ >/dev/null 2>&1
kill $(ps | grep '[l]ua /etc/persistent/wakebot.lua' | awk '{{print $1}}') 2>/dev/null || true
sleep 15
if ps | grep -q '[l]ua /etc/persistent/wakebot.lua'; then
  echo 'controller URL stored; wakebot running'
else
  echo 'controller URL stored; wakebot not detected'
  exit 1
fi
"""
    _, out, err = client.exec_command(script, timeout=120)
    result = out.read().decode(errors="replace")
    error = err.read().decode(errors="replace")
    code = out.channel.recv_exit_status()
    client.close()
    print(result.rstrip())
    if error.strip():
        print("[stderr] " + error.rstrip())
    if code != 0:
        raise SystemExit(code)


if __name__ == "__main__":
    main()
