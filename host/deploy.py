"""Verify or reinstall the WakeSleep relay on an airOS dish.

A FIRMWARE UPGRADE WIPES /etc/persistent. Everything the relay is made of lives
there, so an upgrade silently removes the whole thing: the dish comes back up,
the radio link works, and the only symptom is that Telegram stops answering.
Run this afterwards -- and before, to capture what "correct" looked like.

    python host/deploy.py                 # CHECK ONLY, changes nothing (default)
    python host/deploy.py --apply         # upload whatever differs, then verify
    python host/deploy.py --restore-conf  # recreate wake.conf after a wipe
    python host/deploy.py --host 1.2.3.4  # required, or set DISH_HOST

Check mode is the default on purpose: this pushes code to a device whose
management address is on the far side of a 1.5 km radio link, so looking first
is worth more than one saved keystroke. Only files that actually differ are
uploaded, which makes --apply idempotent and safe to repeat.

wake.conf is NEVER uploaded from here. It holds the bot token and the Forge
pairing secret, and it is deliberately the one piece with no copy in this
directory -- so a wipe means re-entering it, not restoring it from a repo.
"""
import argparse
import getpass
import re
import hashlib
import os
import posixpath
import paramiko

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DEST = "/etc/persistent"

# (local path, remote basename, chmod or None)
# Everything lands flat in /etc/persistent; the directories are for readers of
# the repository, not for the dish.
FILES = [
    (os.path.join(ROOT, "sha256", "sha256.lua"), "sha256.lua", None),
    (os.path.join(ROOT, "sha256", "sha256_test.lua"), "sha256_test.lua", None),
    (os.path.join(ROOT, "bot", "wakebot.lua"), "wakebot.lua", None),
    (os.path.join(ROOT, "bot", "wakebotd.sh"), "wakebotd.sh", "755"),
    (os.path.join(ROOT, "bot", "rc.poststart"), "rc.poststart", "755"),
    (os.path.join(ROOT, "bot", "tg-ca.pem"), "tg-ca.pem", None),
    (os.path.join(ROOT, "bot", "wol.lua"), "wol.lua", "755"),
]
CONF_KEYS = ["TOKEN", "CHATID", "MAC", "BCAST", "PC_IP", "PC_NAME"]
RELAY_KEYS = ["FORGE_RELAY_URL", "RELAY_SECRET"]


def local_md5(path):
    """Hash the bytes as they will land: CRLF normalised to LF, as put() writes."""
    return hashlib.md5(open(path, "rb").read().replace(b"\r\n", b"\n")).hexdigest()


def run(client, command, timeout=60):
    _in, out, err = client.exec_command(command, timeout=timeout)
    o = out.read().decode(errors="replace")
    e = err.read().decode(errors="replace")
    return out.channel.recv_exit_status(), o, e


def put(client, local, remote, mode):
    """Stream to a .part name, then move into place.

    Never write the live path directly: a connection lost mid-transfer would
    leave a truncated script that the supervisor then tries to run.
    """
    body = open(local, "rb").read().replace(b"\r\n", b"\n")
    tmp = remote + ".part"
    _in, out, err = client.exec_command("cat > '%s'" % tmp, timeout=90)
    _in.write(body)
    _in.flush()
    _in.channel.shutdown_write()
    out.read()
    err.read()
    if out.channel.recv_exit_status() != 0:
        raise SystemExit("upload failed: " + remote)
    cmd = "mv '%s' '%s'" % (tmp, remote)
    if mode:
        cmd += " && chmod %s '%s'" % (mode, remote)
    rc, _, e = run(client, cmd)
    if rc != 0:
        raise SystemExit("install failed for %s: %s" % (remote, e.strip()))


def connect(host, password):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=os.environ.get("LB_USER", "ubnt"), password=password,
              look_for_keys=False, allow_agent=False, timeout=15,
              banner_timeout=15, auth_timeout=15)
    return c


def survey(client):
    """Remote md5 of every managed file, plus wake.conf key names and daemon state.

    Only key NAMES are read back from wake.conf -- never the values, which are
    the bot token and the pairing secret.
    """
    paths = " ".join("'%s'" % posixpath.join(DEST, r) for _, r, _ in FILES)
    _, out, _ = run(client, "md5sum %s 2>/dev/null" % paths)
    have = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2:
            have[posixpath.basename(parts[1])] = parts[0]
    _, conf, _ = run(client, "sed -n 's/=.*//p' %s/wake.conf 2>/dev/null" % DEST)
    # Validate the relay pair by SHAPE, not just presence. A key name proves
    # nothing about its value: a broken installer once wrote a line of shell
    # into FORGE_RELAY_URL and a 3-character RELAY_SECRET, and a name-only check
    # cheerfully reported "sleep relay configured" for a config that could only
    # ever produce 401s.
    _, shape, _ = run(
        client,
        "grep -cE '^RELAY_SECRET=[0-9a-f]{64}$' %s/wake.conf 2>/dev/null; "
        "grep -cE '^FORGE_RELAY_URL=https?://[^ ]+$' %s/wake.conf 2>/dev/null" % (DEST, DEST))
    relay_ok = shape.split() == ["1", "1"]
    _, procs, _ = run(client, "ps | grep -c '[l]ua %s/wakebot.lua'" % DEST)
    return have, conf.split(), procs.strip(), relay_ok


def report(have, conf_keys, running, relay_ok):
    todo = []
    for local, remote, mode in FILES:
        got = have.get(remote)
        if got is None:
            state, need = "MISSING", True
        elif got != local_md5(local):
            state, need = "DIFFERS", True
        else:
            state, need = "ok", False
        print("  %-8s %s" % (state, remote))
        if need:
            todo.append((local, remote, mode))

    if not conf_keys:
        print("  MISSING  wake.conf  <-- token and chat id are gone; use --restore-conf")
    else:
        absent = [k for k in CONF_KEYS if k not in conf_keys]
        if absent:
            print("  BROKEN   wake.conf  missing keys: " + ", ".join(absent))
        else:
            present = [k for k in RELAY_KEYS if k in conf_keys]
            if not present:
                detail = "wake only -- no sleep relay"
            elif len(present) == 2 and relay_ok:
                detail = "sleep relay configured"
            else:
                detail = ("SLEEP RELAY CORRUPT -- rerun host/set-relay-secret.py")
            print("  %-8s wake.conf  (%s)" % ("ok" if detail[0] != "S" else "BROKEN", detail))
    print("  daemon running: %s" % ("yes" if running not in ("0", "") else "NO"))
    return todo


def restore_conf(client, host):
    token = getpass.getpass("Bot token (from BotFather): ").strip()
    chatid = getpass.getpass("Your Telegram chat id: ").strip()
    if not token or not chatid.lstrip("-").isdigit():
        raise SystemExit("Refusing: a token and a numeric chat id are both required.")
    mac = input("PC MAC address (aa:bb:cc:dd:ee:ff): ").strip()
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac):
        raise SystemExit("Refusing: that is not a MAC address. A wrong one sends a "
                         "valid magic packet to nobody and reports success.")
    pc_ip = input("PC IP address on the LAN: ").strip()
    bcast = input("Broadcast address [%s.255]: " %
                  pc_ip.rsplit(".", 1)[0]).strip() or (pc_ip.rsplit(".", 1)[0] + ".255")
    pc_name = input("A name for the PC (shown in the bot menu): ").strip() or "the PC"
    body = ["TOKEN=" + token, "CHATID=" + chatid,
            "MAC=" + mac, "BCAST=" + bcast,
            "PC_IP=" + pc_ip, "PC_NAME=" + pc_name]
    # Streamed over stdin so neither value reaches argv, where ps would show it.
    script = "umask 077; cat > %s/wake.conf; chmod 600 %s/wake.conf" % (DEST, DEST)
    _in, out, err = client.exec_command(script, timeout=30)
    _in.write("\n".join(body) + "\n")
    _in.flush()
    _in.channel.shutdown_write()
    out.read()
    err.read()
    if out.channel.recv_exit_status() != 0:
        raise SystemExit("wake.conf write failed")
    print("\n  wake.conf restored (wake only). Add the sleep relay with:")
    print("    python host/set-relay-secret.py %s" % host)


def verify_and_restart(client):
    print("\n-- verifying --")
    rc, out, _ = run(client, 'lua -e \'print(assert(loadfile("%s/sha256.lua"))().self_test())\'' % DEST)
    print("  sha256 self-test: %s" % (out.strip() or "FAILED"))
    if out.strip() != "true":
        raise SystemExit("ABORT: SHA-256 is wrong on this dish, so /sleep would fail "
                         "with 401. Diagnose with: lua %s/sha256_test.lua" % DEST)
    rc, out, _ = run(client, 'lua -e \'local f,e=loadfile("%s/wakebot.lua") print(f and "OK" or e)\'' % DEST)
    print("  wakebot syntax:   %s" % out.strip())
    if out.strip() != "OK":
        raise SystemExit("ABORT: wakebot.lua does not parse; leaving the old daemon running.")

    run(client, "cfgmtd -w -p /etc/", timeout=120)
    print("  flash written")
    run(client, "kill $(ps | grep '[l]ua %s/wakebot.lua' | awk '{print $1}') 2>/dev/null; sleep 15"
        % DEST, timeout=60)
    _, _, running, _ = survey(client)
    print("  daemon running:   %s" %
          ("yes" if running not in ("0", "") else "NO -- check /tmp/wakebot.log"))
    _, log, _ = run(client, "tail -2 /tmp/wakebot.log")
    for line in log.splitlines():
        print("  | " + line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("DISH_HOST"),
                    help="dish management address; or set DISH_HOST")
    ap.add_argument("--apply", action="store_true", help="upload files that differ")
    ap.add_argument("--restore-conf", action="store_true",
                    help="recreate wake.conf (prompts are hidden)")
    args = ap.parse_args()
    if not args.host:
        raise SystemExit("No dish address. Pass --host or set DISH_HOST.")

    for local, _, _ in FILES:
        if not os.path.exists(local):
            raise SystemExit("missing locally, refusing to continue: " + local)

    pw = os.environ.get("LB_PASS") or getpass.getpass("airOS password for %s: " % args.host)
    client = connect(args.host, pw)
    have, conf_keys, running, relay_ok = survey(client)

    print("== %s ==" % args.host)
    todo = report(have, conf_keys, running, relay_ok)

    if args.restore_conf:
        restore_conf(client, args.host)

    if not args.apply:
        if todo:
            print("\n%d file(s) would be uploaded. Re-run with --apply." % len(todo))
        elif not args.restore_conf:
            print("\nEverything matches. Nothing to do.")
        client.close()
        return

    for local, remote, mode in todo:
        print("  uploading %s" % remote)
        put(client, local, posixpath.join(DEST, remote), mode)
    verify_and_restart(client)
    client.close()


if __name__ == "__main__":
    main()
