---
tags:
  - crypto
  - bitsctf
---

# SaveMeFromThisHell — AES (custom) Writeup + Solvers

**Category:** Crypto

## What I Was Given

From `README.md`, I noted:
- The challenge is “AES” and the flag format is `BITSCTF{...}`.

From `aes.py`, I saw:
- It is **not standard AES**:
  - The S-box is custom: `SBOX[x] = gf_pow(x, 23) ^ 0x63`.
  - The number of rounds is only **4** (`AES.ROUNDS = 4`), not 10/12/14.

From `output(1).txt`, I pulled:
- `key_hint` (hex) is a **13-byte prefix** of the AES key.
- `encrypted_flag` (hex) is the flag ciphertext (64 bytes = 4 blocks).
- 1000 known `(plaintext, ciphertext)` pairs (each 16 bytes, hex).

So the AES key is 16 bytes, and I knew 13 bytes → **only 3 bytes were unknown**:
- Search space = `2^(8*3) = 2^24 = 16,777,216` candidates.
That was totally brute-forceable with a fast check.

---

## Attack Plan

1. I parsed `output(1).txt`:
   - read `key_hint`
   - read one (or a few) plaintext/ciphertext sample pairs
   - read `encrypted_flag`
2. I brute-forced the last 3 key bytes:
   - candidate key = `key_hint || b0 || b1 || b2`
   - encrypt one known plaintext block with candidate key
   - if it matches the known ciphertext block, verify with a second sample (optional)
3. I decrypted `encrypted_flag`:
   - ECB mode (it’s block-by-block AES with no IV shown)
   - remove PKCS#7 padding
4. I printed the flag.

---

## Solver 1 — Full brute-force key recovery + flag decryption

> Place this script in the same directory as `aes.py` and `output(1).txt`.

```python
#!/usr/bin/env python3
import binascii
from pathlib import Path

# Import the provided AES implementation
from aes import AES

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("empty")
    pad = data[-1]
    if pad == 0 or pad > 16:
        raise ValueError("bad padding length")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding bytes")
    return data[:-pad]

def parse_output(path: str):
    lines = Path(path).read_text().splitlines()

    key_hint = bytes.fromhex(lines[0].split(":")[1].strip())
    encrypted_flag = bytes.fromhex(lines[1].split(":")[1].strip())

    # samples start after "samples:"
    i = lines.index("samples:") + 1
    samples = []
    for line in lines[i:]:
        if not line.strip():
            continue
        pt_hex, ct_hex = line.split(",")
        pt = bytes.fromhex(pt_hex.strip())
        ct = bytes.fromhex(ct_hex.strip())
        samples.append((pt, ct))

    return key_hint, encrypted_flag, samples

def check_key(key: bytes, samples):
    aes = AES(key)
    # check 2 samples to avoid rare false positives
    for (pt, ct) in samples[:2]:
        if aes.encrypt(pt) != ct:
            return False
    return True

def recover_key(key_hint: bytes, samples):
    assert len(key_hint) == 13, "key_hint must be 13 bytes"
    prefix = key_hint

    # Brute-force 24 bits: 0x000000 .. 0xFFFFFF
    for x in range(1 << 24):
        suffix = bytes([(x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF])
        key = prefix + suffix
        if check_key(key, samples):
            return key

        # tiny progress print (optional)
        if x % 0x200000 == 0 and x != 0:
            print(f"checked {x:#x} candidates...")

    raise RuntimeError("key not found")

def decrypt_flag(key: bytes, encrypted_flag: bytes) -> bytes:
    aes = AES(key)
    if len(encrypted_flag) % 16 != 0:
        raise ValueError("ciphertext not multiple of 16 bytes")

    pt = b"".join(aes.decrypt(encrypted_flag[i:i+16]) for i in range(0, len(encrypted_flag), 16))
    return pkcs7_unpad(pt)

def main():
    key_hint, encrypted_flag, samples = parse_output("output(1).txt")
    print(f"[+] key_hint = {key_hint.hex()} ({len(key_hint)} bytes)")
    print(f"[+] samples  = {len(samples)} blocks")
    print(f"[+] flag ct  = {len(encrypted_flag)} bytes")

    key = recover_key(key_hint, samples)
    print(f"[+] recovered key = {key.hex()}")

    flag = decrypt_flag(key, encrypted_flag)
    print(f"[+] flag = {flag.decode(errors='replace')}")

if __name__ == "__main__":
    main()
