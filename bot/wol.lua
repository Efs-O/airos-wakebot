#!/usr/bin/lua
-- Wake-on-LAN magic packet sender for airOS (Lua 5.1 + LuaSocket).
-- Usage: lua wol.lua [MAC] [dest] [port]
--   dest defaults to the subnet broadcast; pass a host IP to send unicast
--   instead (needs a permanent ARP entry, since a sleeping NIC never replies).

local socket = require("socket")

local mac  = arg[1]
local dest = arg[2]
local port = tonumber(arg[3]) or 9

-- No defaults on purpose. A MAC baked in as a default sends a well-formed magic
-- packet to nobody and reports success, which is the one failure mode that looks
-- exactly like working.
if not mac or not dest then
  -- string.char(10) rather than a backslash escape: this file is edited
  -- through shells and heredocs that mangle one into a real newline, which
  -- leaves an unfinished string and a wol.lua that will not even parse.
  io.stderr:write("usage: lua wol.lua <MAC> <broadcast-or-host-IP> [port]"
                  .. string.char(10))
  os.exit(2)
end

print("luasocket: " .. tostring(socket._VERSION))

-- A magic packet is 6 x 0xFF then the target MAC repeated 16 times = 102 bytes.
local octets = {}
for hex in mac:gmatch("%x%x") do
  octets[#octets + 1] = string.char(tonumber(hex, 16))
end
if #octets ~= 6 then
  io.stderr:write("bad MAC: " .. tostring(mac) .. "\n")
  os.exit(1)
end
local packet = string.rep("\255", 6) .. string.rep(table.concat(octets), 16)

-- udp4() builds the socket immediately. Plain udp() defers creation until the
-- address family is known in LuaSocket 3.x, so setoption() has no socket yet
-- and setsockopt fails -- which is exactly what the first version hit.
local udp = assert(socket.udp4 and socket.udp4() or socket.udp())
local bound, berr = udp:setsockname("*", 0)
if not bound then print("note: setsockname failed: " .. tostring(berr)) end

local bcast, oerr = udp:setoption("broadcast", true)
if not bcast then
  print("note: broadcast option refused (" .. tostring(oerr) ..
        ") - a broadcast dest will likely fail; use a unicast dest + static ARP")
end

local ok, err = udp:sendto(packet, dest, port)
udp:close()

if not ok then
  io.stderr:write("send to " .. dest .. ":" .. port .. " failed: " .. tostring(err) .. "\n")
  os.exit(1)
end

print(string.format("%s  sent %d bytes to %s:%d for %s",
  os.date("%Y-%m-%d %H:%M:%S"), #packet, dest, port, mac))
