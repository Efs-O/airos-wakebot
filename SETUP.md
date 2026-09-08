# Setup, start to finish

From a dish you have never touched to `/wake` working from mobile data. Fifteen
minutes, most of it waiting for Telegram.

The [README](README.md) explains what this is and why it is shaped this way.
This file is just the order to do things in.

---

## Read this before you run anything

**This modifies a network device and can leave it unreachable. Use it at your
own risk. No warranty — see [LICENSE](LICENSE).**

Not affiliated with, endorsed by, or supported by Ubiquiti. Running this may
void your support, and a firmware upgrade will erase it.

What it actually touches:

- writes files into `/etc/persistent` and **commits them to flash** with
  `cfgmtd -w -p /etc/`
- installs `rc.poststart`, which airOS runs on **every boot**
- starts a long-running process that holds an outbound HTTPS connection

Where the real danger is:

- **Interrupting a flash write can brick the device.** `cfgmtd` is the one step
  here with no undo. Do not power-cycle, reboot, or drop the link while
  `deploy.py` is applying — it is a few seconds, and it is the few seconds that
  matter. Do not run it over a link you are about to reconfigure.
- **A remote dish is the risk multiplier, not the code.** If the radio you are
  installing on is the one carrying your management traffic — on a roof, on a
  tower, at the far end of a 1.5 km link — then any mistake that costs you SSH
  costs you a physical trip. **Install on the near dish first** and prove it
  there.
- **A boot hook runs when nobody is watching.** `rc.poststart` is guarded (it
  tests for the daemon and backgrounds it) so a missing or unreadable script is
  a no-op rather than a hang. That guard is why it is written the way it is —
  keep it if you edit the file.

Recovering a dish that stops answering:

1. Power-cycle it. A daemon that failed to start does not survive a reboot as a
   problem; nothing here is loaded before the network is.
2. If SSH answers but the bot does not, nothing is broken at the device level —
   read `/tmp/wakebot.log` and see the table at the end of this file.
3. If nothing answers, airOS has **TFTP recovery mode**: power off, hold the
   reset button, power on while still holding it for ~10 seconds until the LEDs
   cycle, then flash a stock firmware image to `192.168.1.20` with a TFTP
   client. This restores the device and **erases all of this**, which is the
   point — it is a way back, and it is why this is recoverable rather than
   fatal. Look up the procedure for your exact model before you need it.
4. Reset-to-defaults (hold reset ~10 s while running) clears `/etc/persistent`
   too, and is the gentler option when the device still boots.

None of the above is exotic — it is the same exposure as any airOS
customisation. It is written down because "it wipes on firmware upgrade" and
"do not interrupt a flash write" are the two facts most likely to cost someone a
device, and neither is obvious from the outside.

---

## Before you start

**On the dish** — SSH enabled, and its management IP. In the airOS web UI:
*Services → SSH Server → Enable*. Note the address you use to reach the UI; that
is `DISH_HOST` everywhere below.

**On your workstation** — Python 3 and one dependency:

```bash
pip install paramiko
```

**Which device?** Any airOS radio with Lua and LuaSocket. Built and tested on a
LiteBeam 5AC Gen2, airOS 8.7.25. If you have a pair bridging two sites, install
on **one** of them — see *Two dishes, one token* in the README.

---

## 1. Make the bot

In Telegram, message [@BotFather](https://t.me/botfather):

- `/newbot`, answer the two questions, and keep the token it gives you. It looks
  like `123456789:AAE...`.
- Use a **dedicated bot**. If you point this at a token something else already
  long-polls, Telegram answers one of them HTTP 409 and both start missing
  messages at random.

Then get your own chat id, since the bot answers only you:

- Send `/start` to your new bot — it will not reply yet, that is expected.
- Open `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser.
- Read `message.chat.id` out of the JSON. It may be negative; that is fine.

---

## 2. Tell the scripts how to log in

Credentials are passed by environment variable and are never written to a file
by anything in this repository.

```bash
export DISH_HOST=192.0.2.1        # your dish's management address
export LB_USER=ubnt               # airOS default; change if you renamed it
export LB_PASS='your-dish-password'
```

`LB_USER` matters more than it looks. It defaults to `ubnt`, the airOS stock
account, and if you renamed yours the failure is a raw paramiko
`AuthenticationException` traceback that says nothing about usernames. Set it
explicitly and skip that.

Leave `LB_PASS` unset if you would rather be prompted — every script falls back
to a hidden prompt.

---

## 3. Look before you touch

```bash
python host/deploy.py
```

This is check-only and changes nothing — that is the default on purpose. Expect
every file `MISSING` and `wake.conf` missing on a device that has never had this
installed. If you get an auth error, go back to step 2.

---

## 4. Install

```bash
python host/deploy.py --apply
```

Uploads only what differs, then verifies. It **refuses to start the daemon** if
the on-device SHA-256 self-test or the Lua syntax check fails, so a bad upload
leaves the previous state running rather than a broken one.

---

## 5. Create the config

```bash
python host/deploy.py --restore-conf
```

Prompts for the bot token, your chat id, the MAC of the PC to wake, its IP, the
broadcast address, and a display name. Token and chat id are hidden as you type.
The file is written mode 600 and **never leaves the dish** — this repository has
no copy of it, only [`bot/wake.conf.example`](bot/wake.conf.example).

The MAC is validated. A wrong one is the worst failure here: it sends a
perfectly valid magic packet to nobody and reports success.

### Enable Wake-on-LAN on the PC itself

Easy to forget, and nothing on the dish can detect it:

- **BIOS/UEFI** — enable Wake-on-LAN / *Power On by PCIe*.
- **Windows** — Device Manager → your network adapter → *Power Management* →
  allow the device to wake the computer, and *Advanced* → enable the Wake-on-LAN
  / Magic Packet entries.
- **Windows fast startup** puts the machine in a hybrid state that many NICs do
  not wake from. Turn it off if `/wake` does nothing.

---

## 6. Check it

```bash
python host/deploy.py
```

Every file `ok`, `wake.conf` present, `daemon running: yes`. Then in Telegram:

```
/status     the dish answers, and says whether the PC pings
/signal     link signal, rates, capacity
/wake       the magic packet
```

`/help` lists everything. If Telegram stays silent, read the log on the dish:

```bash
ssh $LB_USER@$DISH_HOST 'tail -20 /tmp/wakebot.log'
```

You can also run the link report directly, without disturbing the poller:

```bash
ssh $LB_USER@$DISH_HOST 'lua /etc/persistent/wakebot.lua --report'
```

Do **not** run `wakebot.lua` with no arguments by hand — it falls through into
the polling loop and becomes a second poller on your token, which is the 409
problem above.

---

## 7. Optional: `/sleep`

`/wake` is self-contained. `/sleep` needs something on the PC listening for a
signed request — see *`/sleep` needs a listener* in the README for the wire
format, and [Forge](https://github.com/Efs-O/Forge) for the implementation it
was built against.

Once that listener is running and you have generated its secret:

```bash
export FORGE_RELAY_URL=http://192.0.2.10:8742/v1/sleep   # your PC, not the dish
python host/set-relay-secret.py $DISH_HOST
```

The secret is prompted hidden and streamed over stdin, so it never appears in
`ps` or a shell history. It must be exactly 64 hex characters; anything else is
refused up front rather than becoming an unexplained `401` later.

Never hand-edit those two keys on the dish. A malformed secret still *looks*
like a config, and `deploy.py` will tell you `SLEEP RELAY CORRUPT` rather than
pretending otherwise — but only because it checks their shape, not just that the
keys exist.

---

## After a firmware upgrade, run this again

An airOS firmware upgrade **erases `/etc/persistent`**, which is all of this. The
dish comes back up, the radio link works, and the only symptom is that Telegram
goes quiet.

```bash
python host/deploy.py                 # what is missing?
python host/deploy.py --apply         # put the code back
python host/deploy.py --restore-conf  # only if wake.conf went too
```

Run the check *before* upgrading as well, so you know what "correct" looked like.

---

## When something is wrong

| Symptom | Cause |
|---|---|
| `AuthenticationException` traceback | `LB_USER` — it defaults to `ubnt` |
| Bot silent, `daemon running: NO` | read `/tmp/wakebot.log` on the dish |
| Bot answers erratically, misses messages | two pollers on one token — 409 |
| `/wake` reports success, PC stays off | wrong MAC, or WoL not enabled on the PC |
| `/sleep` gives 401 | secret mismatch — rerun `host/set-relay-secret.py` |
| `SLEEP RELAY CORRUPT` | malformed values in `wake.conf`; rerun the same script |
| Shell script fails naming a file that exists | CRLF line endings — `.gitattributes` pins LF, check your checkout |
