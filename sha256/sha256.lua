-- SHA-256 + HMAC-SHA-256 for airOS (Lua 5.1 + bit32.so).
--
-- Why this file exists: the dish has no `openssl` binary and busybox here ships
-- only md5sum, so there is no way to shell out for a SHA-256.  It does have
-- /lib/lua/bit32.so, which is all a native implementation needs.  Do NOT
-- replace this with `curl -k` or an unsigned request: the whole point is that
-- Forge can tell this dish apart from anything else on the LAN.
--
-- Verified against the NIST SHA-256 vectors and RFC 4231 HMAC cases 1/2/3/6
-- by sha256_test.lua, which runs on the dish itself.

local bit32 = require("bit32")
local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local lshift, rshift = bit32.lshift, bit32.rshift
local MOD = 4294967296

-- CRITICAL: the bit32.so on airOS SATURATES out-of-range arguments instead of
-- reducing them modulo 2^32 as Lua 5.2 specifies -- band(2^32+5, 0xffffffff)
-- answers 0xffffffff, not 5.  Every SHA-256 addition overflows 32 bits, so
-- folding sums with band() pins the whole state to all-ones and the digest is
-- ffff... for every input.  Reduce sums with `% MOD` and never pass a value
-- >= 2^32 into any bit32 function.
local byte, char, rep, sub = string.byte, string.char, string.rep, string.sub

-- bit32.rrotate exists in the 5.2 module but not in every 5.1 backport, so
-- rotate is built from shifts rather than assumed.
local function rrot(x, n)
  return bor(rshift(x, n), band(lshift(x, 32 - n), 0xffffffff))
end

local K = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function be32(n)
  return char(band(rshift(n, 24), 0xff), band(rshift(n, 16), 0xff),
              band(rshift(n, 8), 0xff), band(n, 0xff))
end

local function pad(msg)
  local len = #msg
  local bits = len * 8
  -- 64-bit big-endian length.  Lua 5.1 numbers are doubles, so the high word
  -- is taken by division rather than a shift that would overflow 32 bits.
  local hi = math.floor(bits / 4294967296)
  local lo = bits % 4294967296
  local padlen = 56 - ((len + 1) % 64)
  if padlen < 0 then padlen = padlen + 64 end
  return msg .. "\128" .. rep("\0", padlen) .. be32(hi) .. be32(lo)
end

--- SHA-256 of `msg`.  Returns lowercase hex, or raw 32 bytes when `raw` is true.
local function sha256(msg, raw)
  local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  local data = pad(msg)
  local w = {}
  for block = 1, #data, 64 do
    for i = 0, 15 do
      local a, b, c, d = byte(data, block + i * 4, block + i * 4 + 3)
      w[i + 1] = bor(lshift(a, 24), lshift(b, 16), lshift(c, 8), d)
    end
    for i = 17, 64 do
      local v15, v2 = w[i - 15], w[i - 2]
      local s0 = bxor(rrot(v15, 7), rrot(v15, 18), rshift(v15, 3))
      local s1 = bxor(rrot(v2, 17), rrot(v2, 19), rshift(v2, 10))
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) % MOD
    end
    local a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7
    for i = 1, 64 do
      local S1 = bxor(rrot(e, 6), rrot(e, 11), rrot(e, 25))
      local ch = bxor(band(e, f), band(bnot(e), g))
      local t1 = (h + S1 + ch + K[i] + w[i]) % MOD
      local S0 = bxor(rrot(a, 2), rrot(a, 13), rrot(a, 22))
      local maj = bxor(band(a, b), band(a, c), band(b, c))
      local t2 = (S0 + maj) % MOD
      h, g, f, e = g, f, e, (d + t1) % MOD
      d, c, b, a = c, b, a, (t1 + t2) % MOD
    end
    h0, h1, h2, h3 = (h0 + a) % MOD, (h1 + b) % MOD, (h2 + c) % MOD, (h3 + d) % MOD
    h4, h5, h6, h7 = (h4 + e) % MOD, (h5 + f) % MOD, (h6 + g) % MOD, (h7 + h) % MOD
  end
  local out = be32(h0) .. be32(h1) .. be32(h2) .. be32(h3)
           .. be32(h4) .. be32(h5) .. be32(h6) .. be32(h7)
  if raw then return out end
  return (out:gsub(".", function(ch) return string.format("%02x", byte(ch)) end))
end

--- HMAC-SHA-256.  Returns lowercase hex, which is the form Forge compares.
local function hmac(key, msg)
  if #key > 64 then key = sha256(key, true) end
  key = key .. rep("\0", 64 - #key)
  local ipad, opad = {}, {}
  for i = 1, 64 do
    local k = byte(key, i)
    ipad[i] = char(bxor(k, 0x36))
    opad[i] = char(bxor(k, 0x5c))
  end
  local inner = sha256(table.concat(ipad) .. msg, true)
  return sha256(table.concat(opad) .. inner)
end

--- Cheap startup check.  wakebot.lua asserts this on every daemon start
--- because the failure mode it guards is silent: a saturating bit32 yields a
--- perfectly well-formed 64-char digest that is simply wrong, and the only
--- symptom downstream would be Forge answering 401.
local function self_test()
  return sha256("abc")
      == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    and hmac("Jefe", "what do ya want for nothing?")
      == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
end

-- hmac_hex is the name wakebot.lua uses; hmac is kept as an alias.
return { sha256 = sha256, hmac = hmac, hmac_hex = hmac, self_test = self_test }
