#!/usr/bin/lua
-- Telegram -> Wake-on-LAN relay for airOS.
--
-- Long-polls the Bot API OUTBOUND, so nothing is exposed inbound: no port
-- forward, no inbound firewall hole, and it works from mobile data. Started at
-- boot from /etc/persistent/rc.poststart.
--
-- The token and the owner's chat id live in wake.conf (mode 600), never here.
-- Messages from any other chat id are logged and ignored -- the bot's username
-- is public, so anyone can message it.
--
-- Must be the ONLY getUpdates poller on this token. Telegram answers a second
-- one with HTTP 409, which is why this uses its own bot rather than Forge's.
local cjson = require("cjson")
local sha256 = assert(loadfile("/etc/persistent/sha256.lua"))()

local CONF = "/etc/persistent/wake.conf"
local CA   = "/etc/persistent/tg-ca.pem"
local WOL  = "/etc/persistent/wol.lua"
local TMP  = "/tmp/wakebot.resp"
local LOG  = "/tmp/wakebot.log"

local function log(msg)
  -- /tmp is RAM on this platform, so cap the log rather than let it grow.
  local f = io.open(LOG, "a")
  if f then
    f:write(os.date("%Y-%m-%d %H:%M:%S ") .. tostring(msg) .. "\n")
    local size = f:seek()
    f:close()
    if size and size > 64000 then
      os.execute("tail -c 16000 " .. LOG .. " > " .. LOG .. ".t && mv " .. LOG .. ".t " .. LOG)
    end
  end
end

local cfg = {}
for line in io.lines(CONF) do
  local k, v = line:match("^%s*([%w_]+)%s*=%s*(.-)%s*$")
  if k then cfg[k] = v end
end

-- Every user-visible mention of the machine comes from wake.conf, so nothing
-- in this file names one site's host.
local pc = cfg.PC_NAME or "the PC"
for _, k in ipairs({"TOKEN", "CHATID", "MAC", "BCAST", "PC_IP", "PC_NAME"}) do
  assert(cfg[k] and cfg[k] ~= "", k .. " missing from " .. CONF)
end
local API = "https://api.telegram.org/bot" .. cfg.TOKEN
assert(sha256.self_test(), "sha256.lua self-test failed")
local pending_sleep_until = 0

-- curl writes to a file rather than a pipe: io.popen on Lua 5.1 hides the exit
-- status, and a timeout has to be distinguishable from an empty reply.
local function api(method, query, timeout)
  local cmd = string.format("curl -sS -m %d --cacert '%s' -o '%s' '%s/%s?%s' 2>>%s",
                            timeout, CA, TMP, API, method, query or "", LOG)
  local rc = os.execute(cmd)
  if rc ~= 0 and rc ~= true then return nil end
  local f = io.open(TMP, "r")
  if not f then return nil end
  local body = f:read("*a")
  f:close()
  local ok, data = pcall(cjson.decode, body)
  if not ok then return nil end
  return data
end

local function urlenc(s)
  return (tostring(s):gsub("[^%w%-%._~]",
    function(c) return string.format("%%%02X", string.byte(c)) end))
end

local function say(chat, text)
  api("sendMessage", "chat_id=" .. urlenc(chat) .. "&text=" .. urlenc(text), 20)
end

local function shellquote(value)
  return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function nonce()
  local f = assert(io.open("/dev/urandom", "rb"))
  local bytes = f:read(16)
  f:close()
  return (bytes:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function request_sleep()
  if not cfg.FORGE_RELAY_URL or not cfg.RELAY_SECRET then
    return nil, "WakeForge sleep relay is not configured on this dish."
  end
  local timestamp, request_nonce, body = tostring(os.time()), nonce(), '{"action":"sleep"}'
  local signature = sha256.hmac_hex(cfg.RELAY_SECRET, timestamp .. "." .. request_nonce .. "." .. body)
  local command = "curl -sS -m 15 -o " .. shellquote(TMP) .. " -w '%{http_code}'" ..
    " -H " .. shellquote("X-Forge-Relay-Timestamp: " .. timestamp) ..
    " -H " .. shellquote("X-Forge-Relay-Nonce: " .. request_nonce) ..
    " -H " .. shellquote("X-Forge-Relay-Signature: " .. signature) ..
    " -H 'Content-Type: application/json' --data " .. shellquote(body) ..
    " " .. shellquote(cfg.FORGE_RELAY_URL) .. " 2>>" .. shellquote(LOG)
  local pipe = io.popen(command, "r")
  local status = pipe and pipe:read("*a") or ""
  if pipe then pipe:close() end
  if status:match("^202") then return true end
  return nil, "Forge refused sleep (HTTP " .. (status:match("%d+") or "network error") .. ")."
end

-- Forward fixed lifecycle actions to the Windows Host Controller. The Telegram
-- message contributes only the allow-listed program and action; it never
-- supplies a path, PID, executable, or shell fragment.
local function request_controller(program, action)
  if not cfg.CONTROLLER_URL or not cfg.RELAY_SECRET then
    return nil, "HalluScribe Host Controller is not configured on this relay."
  end
  local timestamp, request_nonce = tostring(os.time()), nonce()
  local body = '{"program":"' .. program .. '"}'
  local signature = sha256.hmac_hex(cfg.RELAY_SECRET, timestamp .. "." .. request_nonce .. "." .. body)
  local path = "/v1/program/" .. program .. "/" .. action
  local command = "curl -sS -m 20 -o " .. shellquote(TMP) .. " -w '%{http_code}'" ..
    " -H " .. shellquote("X-Halluscribe-Timestamp: " .. timestamp) ..
    " -H " .. shellquote("X-Halluscribe-Nonce: " .. request_nonce) ..
    " -H " .. shellquote("X-Halluscribe-Signature: " .. signature) ..
    " -H 'Content-Type: application/json' --data " .. shellquote(body) ..
    " " .. shellquote(cfg.CONTROLLER_URL .. path) .. " 2>>" .. shellquote(LOG)
  local pipe = io.popen(command, "r")
  local status = pipe and pipe:read("*a") or ""
  if pipe then pipe:close() end
  local code = status:match("(%d%d%d)")
  local f = io.open(TMP, "r")
  local response = f and f:read("*a") or ""
  if f then f:close() end
  if code and code:sub(1, 1) == "2" then
    return true, response
  end
  return nil, "Host Controller refused the request (HTTP " .. (code or "network error") .. ")."
end

-- mca-status is the same key=value dump the web UI's front page draws, and
-- wstalist is the association list, so everything Ubiquiti's paid remote
-- management would show for this link is already free on the box. Both are
-- read-only and take no argument, which is why /signal adds no attack surface:
-- it is one more fixed word in the command list, never a shell argument.
local function mca()
  local t = {}
  local p = io.popen("mca-status 2>/dev/null", "r")
  if not p then return t end
  local raw = p:read("*a") or ""
  p:close()
  -- Fields are comma separated and occasionally newline separated; accept both.
  -- %c excludes newline without needing a backslash escape.
  for k, v in raw:gmatch("([%w_]+)=([^,%c]*)") do t[k] = v end
  return t
end

local function peer()
  local p = io.popen("wstalist 2>/dev/null", "r")
  if not p then return nil end
  local raw = p:read("*a") or ""
  p:close()
  local ok, list = pcall(cjson.decode, raw)
  if not ok or type(list) ~= "table" then return nil end
  return list[1]
end

local function dur(seconds)
  local s = tonumber(seconds) or 0
  local d, h, m = math.floor(s / 86400), math.floor(s % 86400 / 3600), math.floor(s % 3600 / 60)
  if d > 0 then return string.format("%dd %dh %dm", d, h, m) end
  return string.format("%dh %dm", h, m)
end

local function snr(sig, noise)
  sig, noise = tonumber(sig), tonumber(noise)
  if not sig or not noise then return "?" end
  return string.format("%d dB", sig - noise)
end

local function link_report()
  local m = mca()
  if not m.signal then
    return "Could not read mca-status. The radio may be reinitialising; try again."
  end
  local out = {}
  local function add(line) out[#out + 1] = line end
  -- essid is usually identical to deviceName on a PTP pair; only worth a
  -- line of the message when it actually differs.
  if m.essid and m.essid ~= m.deviceName then
    add((m.deviceName or "dish") .. " -- " .. m.essid)
  else
    add(m.deviceName or "dish")
  end
  add("")
  add(string.format("Local   %s dBm  (noise %s, SNR %s)",
      m.signal, m.noise or "?", snr(m.signal, m.noise)))
  if m.chain0Signal then
    add(string.format("        chains %s / %s", m.chain0Signal, m.chain1Signal or "?"))
  end
  local far = peer()
  if far then
    -- NOT far.name: wstalist reports the SSID there, not the peer's device
    -- name, so it echoes this dish's own name and reads as if the remote
    -- were the local one. The address and MAC are unambiguous.
    add(string.format("Remote  %s  [%s]",
        tostring(far.lastip or "?"), tostring(far.mac or "?")))
    add(string.format("        %s dBm, noise %s, SNR %s",
        tostring(far.signal), tostring(far.noisefloor), snr(far.signal, far.noisefloor)))
    if far.dl_linkscore then
      add(string.format("        link score %s down / %s up",
          tostring(far.dl_linkscore), tostring(far.ul_linkscore)))
    end
  else
    add("Remote  NOT ASSOCIATED -- the far dish is not linked.")
  end
  add("")
  add(string.format("TX %s / RX %s Mbps  (%s / %s)",
      m.wlanTxRate or "?", m.wlanRxRate or "?", m.txModRate or "?", m.rxModRate or "?"))
  if m.wlanDownlinkCapacity then
    add(string.format("Capacity %d / %d Mbps down/up",
        math.floor((tonumber(m.wlanDownlinkCapacity) or 0) / 1000),
        math.floor((tonumber(m.wlanUplinkCapacity) or 0) / 1000)))
  end
  add(string.format("%s MHz, %s MHz wide, %s m",
      m.freq or "?", m.chanbw or "?", m.distance or "?"))
  add("LAN " .. (m.lanSpeed or "?"))
  add("Uptime " .. dur(m.uptime) .. " (link " .. dur(m.wlanUptime) .. ")")
  return table.concat(out, string.char(10))
end

-- `wakebot.lua --report` prints the report and exits, so /signal can be verified
-- over SSH without sending a Telegram message: the daemon must stay the only
-- getUpdates poller on this token, and a second one collides with HTTP 409.
if arg and arg[1] == "--report" then
  print(link_report())
  os.exit(0)
end

-- Register Telegram's native command menu.  This is the round blue Menu button
-- and slash-command picker shown by Forge's bot; it is account-wide bot
-- metadata, so do it on every daemon start rather than relying on BotFather.
local function register_commands()
  local commands = cjson.encode({
    { command = "wake", description = "Wake " .. pc },
    { command = "sleep", description = "Sleep " .. pc .. " (confirm required)" },
    { command = "status", description = "Check the relay and PC" },
    { command = "signal", description = "Link signal, rates and capacity" },
    { command = "halluscribe", description = "Start or stop HalluScribe" },
    { command = "vscode", description = "Start or stop VS Code" },
    { command = "help", description = "Show WakeForge commands" },
  })
  local result = api("setMyCommands", "commands=" .. urlenc(commands), 30)
  if not result or not result.ok then log("setMyCommands failed") end
end

local function help_text()
  return "WakeForge commands:\n" ..
    "/wake — send a Wake-on-LAN magic packet if " .. pc .. " is asleep\n" ..
    "/sleep — sleep " .. pc .. "; requires /sleep confirm\n" ..
    "/status — show dish uptime and whether the PC answers\n" ..
    "/halluscribe start|stop — control HalluScribe on the PC\n" ..
    "/vscode start|stop — control VS Code on the PC\n" ..
    "/help — show this help\n\n" ..
    "Sleep is available only while Forge is running and the paired relay listener is enabled."
end

local function pc_up()
  return os.execute("ping -c 1 -W 2 " .. cfg.PC_IP .. " >/dev/null 2>&1") == 0
end

local function handle(text, chat)
  local cmd = text:lower():match("^/?(%a+)") or ""
  local argument = text:lower():match("^/?%a+%s*(.-)%s*$") or ""
  if cmd == "wake" then
    if pc_up() then
      say(chat, cfg.PC_NAME .. " is already up (" .. cfg.PC_IP .. ")")
      return
    end
    say(chat, "Sending magic packet to " .. cfg.MAC .. " ...")
    -- Three packets: a single one is enough in testing, but they are 102 bytes
    -- and a lost broadcast costs a whole round trip of the user's patience.
    for _ = 1, 3 do
      os.execute("lua " .. WOL .. " " .. cfg.MAC .. " " .. cfg.BCAST .. " 9 >>" .. LOG .. " 2>&1")
      os.execute("sleep 2")
    end
    -- Both recorded wakes answered 8 s after the packet; 60 s is generous.
    local up = false
    for _ = 1, 20 do
      if pc_up() then up = true break end
      os.execute("sleep 3")
    end
    if up then
      say(chat, cfg.PC_NAME .. " is up (" .. cfg.PC_IP .. ")")
    else
      say(chat, "Packet sent, but " .. cfg.PC_IP ..
                " has not answered in 60 s. It may still be booting, or it was" ..
                " powered off rather than asleep -- WoL cannot help with that.")
    end
    log("wake requested; up=" .. tostring(up))
  elseif cmd == "status" then
    local f = io.open("/proc/uptime", "r")
    local up = f and f:read("*l") or "?"
    if f then f:close() end
    say(chat, string.format("Dish OK. %s is %s.\nDish uptime: %s s",
        cfg.PC_NAME, pc_up() and "UP" or "not answering", (up:match("^(%d+)") or "?")))
  elseif cmd == "signal" then
    say(chat, link_report())
  elseif cmd == "halluscribe" or cmd == "vscode" then
    if argument ~= "start" and argument ~= "stop" then
      say(chat, "Use /" .. cmd .. " start or /" .. cmd .. " stop.")
      return
    end
    local ok, detail = request_controller(cmd, argument)
    say(chat, ok and (cmd .. " " .. argument .. " accepted.\n" .. detail) or detail)
  elseif cmd == "help" or cmd == "start" then
    say(chat, help_text())
  elseif cmd == "sleep" then
    if argument == "confirm" then
      if pending_sleep_until < os.time() then
        say(chat, "Nothing to confirm. Send /sleep first; confirmation expires after 90 seconds.")
      else
        pending_sleep_until = 0
        local ok, err = request_sleep()
        say(chat, ok and ("Forge accepted sleep for " .. cfg.PC_NAME .. ".") or err)
      end
    else
      if not pc_up() then
        say(chat, cfg.PC_NAME .. " is not answering. Use /wake instead.")
      else
        pending_sleep_until = os.time() + 90
        say(chat, "About to sleep " .. cfg.PC_NAME .. ". Send /sleep confirm within 90 seconds.")
      end
    end
  else
    say(chat, help_text())
  end
end

-- Drop any backlog before the loop starts, so a reboot cannot replay an old
-- /wake and boot the machine unasked.
local offset = 0
local seed = api("getUpdates", "offset=-1&timeout=0", 30)
if seed and seed.result and #seed.result > 0 then
  offset = seed.result[#seed.result].update_id + 1
end
log("started, offset=" .. offset)
register_commands()

while true do
  local d = api("getUpdates", "offset=" .. offset .. "&timeout=50&allowed_updates=%5B%22message%22%5D", 70)
  if d and d.ok and d.result then
    for _, up in ipairs(d.result) do
      offset = up.update_id + 1
      local m = up.message
      if m and m.text and m.chat then
        if tostring(m.chat.id) == cfg.CHATID then
          handle(m.text, m.chat.id)
        else
          log("ignored message from chat " .. tostring(m.chat.id))
        end
      end
    end
  else
    -- Network blip, or a 409 because a second poller exists. Back off instead
    -- of spinning on the API.
    os.execute("sleep 5")
  end
end
