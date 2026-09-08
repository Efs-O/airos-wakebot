-- Self-test for sha256.lua.  Run ON THE DISH: lua /etc/persistent/sha256_test.lua
-- NIST SHA-256 vectors + RFC 4231 HMAC-SHA-256 cases 1, 2, 3 and 6.
-- Case 6 uses a 131-byte key, which is the only case that exercises the
-- "key longer than the block size gets hashed first" branch.

package.path = "/etc/persistent/?.lua;" .. package.path
local s = require("sha256")
local fail = 0

local function check(label, got, want)
  if got == want then
    print("ok    " .. label)
  else
    fail = fail + 1
    print("FAIL  " .. label .. "\n  got  " .. got .. "\n  want " .. want)
  end
end

check("sha256 empty", s.sha256(""),
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
check("sha256 abc", s.sha256("abc"),
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("sha256 448bit", s.sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
-- Multi-block, and length past the one-block padding boundary.
check("sha256 1000x a", s.sha256(string.rep("a", 1000)),
  "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3")

check("rfc4231 case1", s.hmac(string.rep("\11", 20), "Hi There"),
  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
check("rfc4231 case2", s.hmac("Jefe", "what do ya want for nothing?"),
  "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
check("rfc4231 case3", s.hmac(string.rep("\170", 20), string.rep("\221", 50)),
  "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
check("rfc4231 case6", s.hmac(string.rep("\170", 131),
  "Test Using Larger Than Block-Size Key - Hash Key First"),
  "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")

if fail == 0 then print("\nALL PASS") else print("\n" .. fail .. " FAILED") end
os.exit(fail == 0 and 0 or 1)
