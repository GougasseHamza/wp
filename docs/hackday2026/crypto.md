---
tags:
  - crypto
  - hackday2026
---

# As Small As Possible (DH + AES-GCM)

**Category:** Crypto

## TL;DR
- The server accepts **arbitrary Diffie–Hellman public keys** without subgroup checks, so I could force Alice’s shared secret into tiny factors of `p-1`.
- Recovering Alice’s exponent modulo each small prime and recombining with CRT let me derive the real shared secret and decrypt the intercepted AES-GCM traffic.

## 1) Recon: what the service does
- When I connected to the challenge I saw an intercepted AES-GCM payload (`iv`, `ciphertext`, `tag`) and a menu to interact with Alice or Bob.
- Selecting **Alice** printed Alice’s DH public key and the modulus `p`, then prompted for my DH public key. Alice computes `s = Y^a mod p`, derives an AES key from `s`, and returns a JSON AES-GCM message using that key.

## 2) Key derivation discovery (using the “1 trick”)
- Sending `Your Key = 1` forced the shared secret to 1 since `1^a == 1 mod p`.
- Alice encrypts a “welcome banner” that I recognized as known plaintext after trying different KDF guesses.
- The working KDF was `AESkey = SHA256(str(shared_secret).encode())`, i.e., `sha256(str(s).encode()).digest()`.

## 3) The real vulnerability: no subgroup validation
- Because the server never checks subgroup membership, any element whose order divides `p-1` is accepted. In `Z_p^*`, orders are factors of `p-1`.
- Sending an element of a small order `q | (p-1)` confines the shared secret `s = h^a` to at most `q` values, so I could brute-force `a mod q` using the known plaintext and AES-GCM tag verification.

## 4) How to get an element of order `q`
For each small prime factor `q` of `p-1`, I did:
1. Choose random `r` in `[2, p-2)`.
2. Compute `h = r^((p-1)/q) mod p`.
3. If `h != 1`, it has order `q` with overwhelming probability. I used that as my public key to communicate with Alice.

## 5) Recover `a mod q` using Alice + tag verification
1. I sent Alice `Your Key = h` (order `q`) and collected `(iv, ciphertext, tag)`.
2. For each candidate `e in [0, q-1]`, I computed `s_e = h^e mod p`, derived `key = sha256(str(s_e).encode()).digest()`, and attempted AES-GCM decrypt with the known welcome banner.
3. The unique `e` that decrypted correctly (and verified the tag) gave `a ≡ e mod q`.

## 6) Reconstruct Alice’s private exponent with CRT
1. I factored `p-1 = ∏ q_i` into its prime factors (all quite small since `p-1` is smooth).
2. I repeated the above step for each `q_i`, collecting congruences `a ≡ e_i mod q_i`.
3. I applied the Chinese Remainder Theorem to reconstruct `a mod (p-1)`.

## 7) Decrypt the intercepted traffic (get the flag)
1. I computed the real shared secret with Bob’s public key: `s = (BobPub)^a mod p`.
2. I derived the AES key using the discovered KDF (`sha256(str(s).encode()).digest()`).
3. I decrypted the intercepted AES-GCM payload and extracted `HACKDAY{...}`.

## 8) Why the challenge name fits
- “As small as possible” hints that the private secret can be forced into **tiny subgroups**, making brute-force over those small sets practical and enabling full exponent recovery.
