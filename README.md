# airos-wakebot

Wake and sleep a PC from Telegram, with the bot running **on a Ubiquiti airOS
radio** rather than on the PC it controls.

The radio is the point. A machine that is asleep cannot run the thing that wakes
it, so anything living on the PC is useless exactly when you need it. A LiteBeam
bridging two sites is already powered, already on the LAN, and already up — it
just needed something to run.

It long-polls the Telegram Bot API **outbound**, so there is no port forward, no
dynamic DNS, no inbound firewall hole, and it works from mobile data.

Tested on a **LiteBeam 5AC Gen2, airOS 8.7.25** (MIPS `ar934x`, 62 MB RAM). It
should suit any airOS device with Lua and LuaSocket.

> [!WARNING]
> **This modifies a network device and can leave it unreachable. Use it at your
> own risk, with no warranty.** It writes to `/etc/persistent`, commits to flash
> with `cfgmtd`, and installs a boot hook. Interrupting a flash write can brick
> the device, and a firmware upgrade erases everything here.
>
> Install on a dish you can physically reach before one on a roof or at the far
> end of a link. Recovery paths and the full list of what it touches are in
> [SETUP.md](SETUP.md#read-this-before-you-run-anything).
>
> Not affiliated with or endorsed by Ubiquiti.

---

## The interesting part: airOS `bit32` is broken

If you only take one thing from this repository, take this.

airOS ships `/lib/lua/bit32.so`, so SHA-256 in pure Lua looks straightforward.
It is not. **That module saturates out-of-range arguments instead of reducing
them modulo 2³²**, contrary to the Lua 5.2 specification:

```lua
bit32.band(2^32 + 5, 0xffffffff)  --> 4294967295   (spec says 5)
```

Every addition in SHA-256 overflows 32 bits. A textbook implementation folds
those sums with `band`, which on this platform pins the entire state to all-ones
— so **every digest is `ffff…ff`, for every input**.

What makes it expensive is the shape of the failure. A wrong digest is still a
well-formed 64-character hex string. Nothing errors, nothing warns, and the only
downstream symptom is an HTTP 401 from whatever you were authenticating to. It
is entirely reasonable to conclude the platform simply has no crypto — there is
no `openssl` binary and busybox provides only `md5sum` — and to go looking for a
different protocol instead. That conclusion is wrong, and this repository is
partly a record of it being wrong.

The fix is to reduce every sum with `%` and never hand a value ≥ 2³² to any
`bit32` function:

```lua
local t1 = (h + S1 + ch + K[i] + w[i]) % 4294967296
```

`sha256/sha256.lua` is a standalone, dependency-free SHA-256 and HMAC-SHA-256
for this environment. `sha256/sha256_test.lua` runs the NIST vectors and
RFC 4231 HMAC cases 1, 2, 3 and 6 **on the device**, which is the only place the
result means anything — the same code passes on a developer machine whether or
not `bit32` is sane.

```
# on the dish
lua /etc/persistent/sha256_test.lua
```

Note also that this Lua is built `(double int32)`: `string.format("%08x", n)`
raises *"integer expected, got number"* for values ≥ 2³¹. Format bytes
individually with `%02x`.

### Verified on the device, including the obvious alternative

Measured on airOS 8.7.25, not inferred:

```
_VERSION                     Lua 5.1
band(5, 0xffffffff)          5             correct
band(2^32 + 5, 0xffffffff)   4294967295    spec says 5
bxor(2^32 + 1, 0)            4294967295    spec says 1
rshift(2^32 + 256, 8)        16777215      spec says 1
```

**[pure_lua_SHA](https://github.com/Egor-Skriptunoff/pure_lua_SHA) also works
here** — tested, `sha256("abc")` matches the NIST vector exactly. It escapes the
trap by not falling into it: this is Lua **5.1** with no `bit` library present,
so it selects its pure-arithmetic branch and never calls `bit32` at all. Its
`bit32` branch is for Lua 5.2, which is not what airOS ships. So use it if you
want SHA-1/3, BLAKE, HMAC and base64 from one well-tested library.

`sha256/sha256.lua` here is 125 lines against its 276 KB, needs nothing but the
standard library, and is small enough to read in full before trusting it with an
authentication path — which is why this repository has its own. That is a size
and auditability argument, not a correctness one.

The `bit32` finding still stands on its own, and it bites the moment you write
bitwise code yourself on this platform, or run anything that picks the `bit32`
branch. It is a real, undocumented deviation from the Lua 5.2 specification, and
the failure is silent.

---

## What it does

| Command | |
|---|---|
| `/wake` | Sends a Wake-on-LAN magic packet |
| `/sleep` | Asks the PC to suspend — needs a listener, see below. Requires `/sleep confirm` |
| `/halluscribe start` / `stop` | Signed request to the fixed Windows Host Controller |
| `/vscode start` / `stop` | Signed request to the fixed Windows Host Controller |
| `/signal` | Link signal, noise, SNR, chains, TX/RX rates, capacity, distance, uptimes |
| `/status` | Dish uptime, and whether the PC answers a ping |
| `/help` | The above |

`/signal` is worth calling out: it reads `mca-status` and `wstalist`, the same
sources the web UI front page uses. Ubiquiti moved remote management behind a
paid tier, but these are local reads on a device you own, and nothing about them
is gated.

Only one chat id may command the bot. The bot's username is public, so anyone
can message it; every other sender is logged and ignored.

---

## Repository layout

```
sha256/   sha256.lua, sha256_test.lua   -- standalone, useful on its own
bot/      what runs on the dish
host/     deploy and configure it, from your workstation
```

### `bot/`

| File | |
|---|---|
| `wakebot.lua` | The poller and command handler |
| `wakebotd.sh` | Supervisor — restarts the poller if it dies |
| `rc.poststart` | Boot hook, sourced by airOS `rc.funcs` |
| `wol.lua` | Magic packet sender (LuaSocket) |
| `tg-ca.pem` | Pinned roots for `api.telegram.org` |
| `wake.conf.example` | Copy to `/etc/persistent/wake.conf`, mode 600 |

### `host/`

| File | |
|---|---|
| `deploy.py` | Check-first installer. **Run it after any firmware upgrade.** |
| `set-relay-secret.py` | Installs the `/sleep` pairing secret |
| `set-controller-url.py` | Installs the non-secret Windows controller URL |

---

## Install

**New here? Follow [SETUP.md](SETUP.md)** — bot creation, credentials, the
order to run things in, and what to do when it does not work. The summary:

Requires `paramiko` on the workstation. SSH must be enabled on the dish.
Credentials come from `LB_USER` / `LB_PASS`; `LB_USER` defaults to `ubnt`, and
a renamed account fails as a bare paramiko traceback.

```bash
export DISH_HOST=<dish management ip>

python host/deploy.py                 # CHECK ONLY — the default, changes nothing
python host/deploy.py --apply         # upload whatever differs, then verify
python host/deploy.py --restore-conf  # create wake.conf (prompts, hidden)
# after the controller is installed on the PC
python host/set-controller-url.py --host <dish-management-ip> --url http://<pc-lan-ip>:8787
```

Check mode is the default deliberately: this pushes code to a device whose
management address may be on the far side of a radio link, and looking first is
worth more than a saved keystroke. Only files that actually differ are uploaded,
so `--apply` is idempotent.

`deploy.py` refuses to restart the daemon if the on-device SHA-256 self-test or
the Lua syntax check fails, and it **never uploads `wake.conf`** — that file
holds the token and the pairing secret and deliberately has no copy in this
repository.

The lifecycle commands use the same `RELAY_SECRET` as the signed controller
requests, but the controller URL is configured separately because it is not a
secret. The dish sends only fixed program names and actions; it never sends a
path, PID, or shell command.

### A firmware upgrade wipes everything

Everything here lives in `/etc/persistent`, and an airOS firmware upgrade
silently erases it. The dish comes back up, the radio link works, and the only
symptom is that Telegram stops answering. That is why `deploy.py` exists and why
it leads with a check: run it before an upgrade to capture what "correct" looked
like, and after to put it back.

---

## `/sleep` needs a listener on the PC

`/wake` is self-contained — a magic packet is fire-and-forget. `/sleep` is not:
something on the PC has to receive the request and suspend the machine.

This repository speaks the wire format but does not implement the receiver. Any
listener that verifies the signature below will work. The one it was built
against is in [Forge](https://github.com/Efs-O/Forge), a VS Code extension whose
`RelaySleepServer` binds to a private-LAN address, is off unless configured, and
holds the shared secret in VS Code SecretStorage.

```
POST /v1/sleep
X-Forge-Relay-Timestamp: <unix seconds>
X-Forge-Relay-Nonce:     <random>
X-Forge-Relay-Signature: <lowercase hex>

{"action":"sleep"}
```

The signature is `HMAC-SHA-256(secret, "<timestamp>.<nonce>.<body>")`. The
receiver should enforce a clock-skew window, keep a nonce cache against replay,
and pin the source address.

Be clear-eyed about what this authentication is for. It stops a stray or
replayed request from suspending your machine. It is not a security boundary
against someone already on your LAN, and the worst case if it fails is that your
PC goes to sleep.

To pair:

```bash
export DISH_HOST=<dish ip>
export FORGE_RELAY_URL=http://<pc-ip>:8742/v1/sleep
python host/set-relay-secret.py
```

Both prompts are hidden, and the secret is streamed over stdin rather than
passed as an argument, so it never appears in `ps` or a shell history.

---

## Two dishes, one token

If you have more than one radio, run the bot on **one** of them. Telegram
answers a second `getUpdates` poller on the same token with HTTP 409, and both
pollers then miss messages at random.

For the same reason, use a **dedicated bot** rather than sharing one with another
service that also long-polls.

---

## Things that cost time here, recorded so they cost you less

- **`bit32` saturates.** Above. The one that mattered.
- **No `openssl`, no SHA utility, only `md5sum`.** The natural conclusion —
  "this device cannot do HMAC" — is wrong.
- **dropbear has no `sftp-server`**, and the exec command string is capped around
  8.5 KB. Sending a file as part of the command fails past roughly 12 KB with a
  bare `EOFError`. Stream over stdin into a `.part` file and move it into place.
- **Never feed a shell its script and its input on the same pipe.** `sh` reads a
  piped script incrementally, so a `read` inside it consumes the *next line of
  the script*. This half-executed, wrote a line of shell into a config value, and
  only then died — a corrupt config from a command that merely looked like it had
  failed.
- **busybox `ash` has no `timeout`.** Use `cmd & P=$!; (sleep N; kill -9 $P) & wait $P`.
- **`wstalist` reports the SSID in `name`**, not the peer's device name — so a
  naive `/signal` echoes the local dish's own name and reads as though the remote
  were the local one. Report the address and MAC instead.
- **`rc.softrestart save` silently writes nothing** after a `test`.
- **Verify config by shape, not by key name.** A name-only check once reported
  "sleep relay configured" for a three-character secret that could only ever
  produce 401s.

---

## Licence

MIT. See [LICENSE](LICENSE).

No affiliation with Ubiquiti. Running this modifies `/etc/persistent` on your
radio and may void support; a firmware upgrade will erase it. See the warning at
the top and [SETUP.md](SETUP.md#read-this-before-you-run-anything).
