# As Small As Possible (DH + AES-GCM)

## TL;DR
- The server accepts **arbitrary Diffie–Hellman public keys** without subgroup checks, so we can force Alice’s shared secret into tiny factors of `p-1`.
- Recovering Alice’s exponent modulo each small prime and recombining with CRT recovers the full exponent, letting us derive the real shared secret and decrypt the intercepted AES-GCM traffic.

## 1) Recon: what the service does
- Connecting to the challenge reveals an intercepted AES-GCM payload (`iv`, `ciphertext`, `tag`) and a menu to interact with Alice or Bob.
- Selecting **Alice** prints Alice’s DH public key and the modulus `p`, then prompts for our DH public key. Alice computes `s = Y^a mod p`, derives an AES key from `s`, and returns a JSON AES-GCM message using that key.

## 2) Key derivation discovery (using the “1 trick”)
- Sending `Your Key = 1` forces the shared secret to 1 since `1^a == 1 mod p`.
- Alice encrypts a “welcome banner” that we recognize as known plaintext after trying different KDF guesses.
- The working KDF is `AESkey = SHA256(str(shared_secret).encode())`, i.e., `sha256(str(s).encode()).digest()`.

## 3) The real vulnerability: no subgroup validation
- Because the server never checks subgroup membership, any element whose order divides `p-1` is accepted. In `Z_p^*`, orders are factors of `p-1`.
- Sending an element of a small order `q | (p-1)` confines the shared secret `s = h^a` to at most `q` values, so we can brute-force `a mod q` using the known plaintext and AES-GCM tag verification.

## 4) How to get an element of order `q`
For each small prime factor `q` of `p-1`:
1. Choose random `r` in `[2, p-2)`.
2. Compute `h = r^((p-1)/q) mod p`.
3. If `h != 1`, it has order `q` with overwhelming probability. Use that as our public key to communicate with Alice.

## 5) Recover `a mod q` using Alice + tag verification
1. Send Alice `Your Key = h` (order `q`) and collect `(iv, ciphertext, tag)`.
2. For each candidate `e in [0, q-1]`, compute `s_e = h^e mod p`, derive `key = sha256(str(s_e).encode()).digest()`, and attempt AES-GCM decrypt with the known welcome banner.
3. The unique `e` that decrypts correctly (and verifies the tag) gives `a ≡ e mod q`.

## 6) Reconstruct Alice’s private exponent with CRT
1. Factor `p-1 = ∏ q_i` into its prime factors (all quite small since `p-1` is smooth).
2. Repeat the above step for each `q_i`, collecting congruences `a ≡ e_i mod q_i`.
3. Apply the Chinese Remainder Theorem to reconstruct `a mod (p-1)`.

## 7) Decrypt the intercepted traffic (get the flag)
1. Compute the real shared secret with Bob’s public key: `s = (BobPub)^a mod p`.
2. Derive the AES key using the discovered KDF (`sha256(str(s).encode()).digest()`).
3. Decrypt the intercepted AES-GCM payload and extract `HACKDAY{...}`.

## 8) Why the challenge name fits
- “As small as possible” hints that the private secret can be forced into **tiny subgroups**, making brute-force over those small sets practical and enabling full exponent recovery.

## 9) Fix / lesson
- Validate every received DH public key: ensure `2 ≤ Y ≤ p-2` and check subgroup membership (e.g., `Y^q ≡ 1 mod p` when using a subgroup of order `q`).
- Prefer safe-prime DH groups or standard elliptic curves where subgroup checks are implicit.
- Never accept user-controlled public keys without strong validation to avoid small-subgroup and confinement attacks.
