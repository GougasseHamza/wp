---
tags:
  - crypto
  - upctf
---

# upCTF Crypto Writeup

## Challenge

I was given the following challenge:

```python
from Crypto.Util.number import *
from Crypto.Hash import SHA256
import secrets

def hsh(x):
  h = SHA256.new()
  h.update(x)
  return int.from_bytes(h.digest())
  

for i in range(10):
  S=set()
  p=getPrime(70)
  print(f"{p=}")
  x=secrets.randbelow(p)
  while True:
    m1=input("m1=")
    if "Stop" in m1:
      break
    m1=bytes.fromhex(m1)
    if m1 in S:
      print("NO!")
      exit(0)
    S.add(m1)
    m2=bytes.fromhex(input("m2="))
    if m2 in S:
      print("NO!")
      exit(0)
    S.add(m2)
    
    res=pow(x,hsh(m1),p)+pow(x,hsh(m2),p)
    res%=p
    print(f"{res=}")
  
  x2=int(input("x="))
  if x2!=x:
    print("FAIL!")
    exit(0)

print(open("flag.txt","r").read())
```

The flag I recovered was:

`upCTF{Wagner_algorithm_is_very_OP-Aj97UrTu5e9639b1}`

## My first observations

I started with the obvious simplification:

- The exponents are `SHA256(m)` interpreted as a huge integer.
- Since the computation is `pow(x, hsh(m), p)`, the exponent is really reduced modulo `p-1` for nonzero `x`.
- So I can define
  `e(m) = SHA256(m) mod (p-1)`,
  and every query is just
  `res = x^e1 + x^e2 mod p`.

I also checked for parser bugs and protocol bugs. There was nothing useful:

- `bytes.fromhex()` was strict enough.
- The message reuse check was real.
- `"Stop"` only stopped the query loop.
- There was no accidental leak of `x`.

So I needed an actual algebraic attack.

## The baseline idea I rejected

The most obvious attack is an exact exponent collision.

If I find two distinct messages `m1, m2` such that:

`e(m1) = e(m2) mod (p-1)`,

then one query gives:

`res = x^e + x^e = 2*x^e mod p`.

If `gcd(e, p-1) = 1`, then I can recover:

`x = (res / 2)^(e^{-1} mod (p-1)) mod p`.

This works, but it costs about a birthday collision in a 70-bit space:

- expected work: about `2^35` hashes,
- and that has to be done repeatedly across 10 rounds.

That was too expensive.

## The better idea: I only needed a repeated difference

The real breakthrough was noticing that I did not need an exact collision at all.

Suppose I have four messages with exponents:

- `e_a`
- `e_b`
- `e_c`
- `e_d`

and they satisfy:

`e_a + e_d = e_b + e_c mod (p-1)`.

Equivalently:

`e_b - e_a = e_d - e_c = c mod (p-1)`.

Now I make two oracle queries:

1. query `(m_a, m_c)`:
   `r1 = x^e_a + x^e_c mod p`

2. query `(m_b, m_d)`:
   `r2 = x^e_b + x^e_d mod p`

Since `e_b = e_a + c` and `e_d = e_c + c`, I get:

`r2 = x^(e_a + c) + x^(e_c + c)`

`r2 = x^c * (x^e_a + x^e_c)`

`r2 = x^c * r1 mod p`

So:

`x^c = r2 / r1 mod p`

and if `gcd(c, p-1) = 1`, then:

`x = (r2 / r1)^(c^{-1} mod (p-1)) mod p`

That was the key. I had turned the problem into:

> find four messages whose exponent residues satisfy one modular 4-sum relation.

## Turning it into a generalized birthday problem

Now I had a standard shape:

`e_a + e_d - e_b - e_c = 0 mod (p-1)`

or equivalently:

`e_a + e_d = e_b + e_c mod (p-1)`.

This is exactly the kind of thing Wagner's generalized birthday algorithm is meant for.

For a random 70-bit modulus:

- the exact collision attack costs about `2^(70/2) = 2^35`,
- while the 4-list generalized birthday attack costs about `2^(70/3)`,
- which is around `2^23.3`.

That is a massive reduction.

In practice on this box, that meant:

- roughly 12 million residues per list was often enough,
- 16 million residues handled the unlucky rounds,
- and one full round typically took a few tens of seconds.

That was absolutely practical against the live service.

## The concrete Wagner-style construction I used

I split my candidates into four disjoint lists:

- list `A`
- list `B`
- list `C`
- list `D`

I encoded messages as 8-byte values with the top nibble identifying the list, so all four messages were automatically distinct:

- `A`: `0x0...`
- `B`: `0x1...`
- `C`: `0x2...`
- `D`: `0x3...`

Then I searched for:

`e_a + e_d = e_b + e_c mod n`

where `n = p - 1`.

I did not compare all quadruples directly. Instead, I used a bucketed meet-in-the-middle.

### Step 1: build a right-hand list from `B + C`

For each `e_b` and `e_c`, I wanted sums where the low `t` bits were zero after either:

- no wrap: `e_b + e_c`
- one wrap: `e_b + e_c - n`

So for every candidate pair, I stored:

- `q = (e_b + e_c) >> t` if low `t` bits were zero, or
- `q = (e_b + e_c - n) >> t` if low `t` bits were zero after subtracting `n`.

That gave me a compressed right-hand list keyed by the high bits.

### Step 2: scan `A + D`

Then I generated candidate sums on the left:

- `e_a + e_d`
- `e_a + e_d - n`

again only keeping the ones with low `t` bits zero.

For each one, I looked for the same quotient `q` in the right-hand list.

When the quotients matched, I checked the full equality:

`e_a + e_d = e_b + e_c mod n`

If that equality held and `gcd(e_b - e_a, n) = 1`, I was done.

## Why the query order matters

My searcher prints five lines:

1. `m_a`
2. `m_c`
3. `m_b`
4. `m_d`
5. `c = e_b - e_a mod (p-1)`

That ordering is deliberate.

I query:

1. `(m_a, m_c)` to get `r1`
2. `(m_b, m_d)` to get `r2`

Then I compute:

`x = ((r2 * r1^{-1}) mod p) ^ (c^{-1} mod (p-1)) mod p`

This is exactly the algebra derived above.

## Edge cases I handled

There were a few real edge cases.

### 1. `gcd(c, p-1) != 1`

If `c` is not invertible modulo `p-1`, then recovering `x` from `x^c` is ambiguous.

I avoided this by rejecting such matches in the searcher.

### 2. Some rounds miss at 12 million

The `2^(70/3)` estimate is an expectation, not a guarantee.

Some rounds did not produce a usable relation with:

- `L = 12000000`
- `t = 24`

So I added fallback settings:

- `L = 16000000, t = 24`
- `L = 16000000, t = 23`

That solved the unlucky rounds.

### 3. Message reuse is forbidden

The service keeps a set of used byte strings, so I needed all four query messages to be distinct.

Using separate list identifiers in the high nibble made that automatic.

## The attack workflow I used live

For each round:

1. Read `p`.
2. Run the local relation search against `n = p - 1`.
3. Get four messages and the shift `c`.
4. Query `(m_a, m_c)` and parse `r1`.
5. Query `(m_b, m_d)` and parse `r2`.
6. Compute:
   `x = ((r2 / r1) mod p)^(c^{-1} mod (p-1)) mod p`
7. Send `Stop`.
8. Send `x`.

I automated the whole thing in a small remote solver.

## Complexity

The important comparison is:

- exact collision:
  about `2^35` SHA-256 evaluations
- 4-list generalized birthday:
  about `2^(70/3) ~= 2^23.3`

In other words, Wagner's algorithm is exactly what made this challenge practical.

That is why the flag text saying Wagner is OP is accurate.

## Build and run

I compiled the searcher like this:

```bash
g++ -O3 -march=native relation_search.cpp -lcrypto -o relation_search
```

Then I ran the remote solver against the service.

## Solver 1: relation_search.cpp

This is the compiled Wagner-style 4-list searcher I used.

```cpp
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using u128 = unsigned __int128;

struct RightEntry {
    uint64_t q;
    uint64_t meta;
};

static inline std::string u128_to_string(u128 x) {
    if (x == 0) return "0";
    std::string s;
    while (x > 0) {
        s.push_back(char('0' + (x % 10)));
        x /= 10;
    }
    std::reverse(s.begin(), s.end());
    return s;
}

static inline u128 parse_u128(const std::string& s) {
    u128 x = 0;
    for (char c : s) {
        if (c < '0' || c > '9') continue;
        x = x * 10 + (c - '0');
    }
    return x;
}

static inline uint64_t make_msg(int list_id, uint32_t idx) {
    return (uint64_t(list_id) << 60) | uint64_t(idx);
}

static inline std::array<unsigned char, 8> to_be8(uint64_t x) {
    std::array<unsigned char, 8> out{};
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<unsigned char>(x & 0xff);
        x >>= 8;
    }
    return out;
}

static inline std::string hex_msg(uint64_t x) {
    auto b = to_be8(x);
    static const char* H = "0123456789abcdef";
    std::string s;
    s.resize(16);
    for (int i = 0; i < 8; ++i) {
        s[2 * i] = H[b[i] >> 4];
        s[2 * i + 1] = H[b[i] & 15];
    }
    return s;
}

static inline u128 sha256_mod_u128(uint64_t msg, u128 mod) {
    auto in = to_be8(msg);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(in.data(), in.size(), digest);

    u128 r = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        r = (r * 256 + digest[i]) % mod;
    }
    return r;
}

static void fill_residues(int list_id, uint32_t count, u128 mod, std::vector<u128>& out) {
    out.resize(count);
    unsigned threads = std::max(1u, std::thread::hardware_concurrency());
    threads = std::min(threads, 2u);
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; ++t) {
        uint32_t lo = (uint64_t(count) * t) / threads;
        uint32_t hi = (uint64_t(count) * (t + 1)) / threads;
        pool.emplace_back([=, &out]() {
            for (uint32_t i = lo; i < hi; ++i) {
                out[i] = sha256_mod_u128(make_msg(list_id, i), mod);
            }
        });
    }
    for (auto& th : pool) th.join();
}

static inline uint64_t lowbits(u128 x, uint32_t mask) {
    return static_cast<uint64_t>(x) & mask;
}

static inline uint64_t gcd_u128(u128 a, u128 b) {
    while (b != 0) {
        u128 r = a % b;
        a = b;
        b = r;
    }
    return static_cast<uint64_t>(a);
}

static void build_bucket_index(
    const std::vector<u128>& vals,
    uint32_t t,
    std::vector<uint32_t>& head,
    std::vector<uint32_t>& idx
) {
    uint32_t B = 1u << t;
    uint32_t mask = B - 1;
    head.assign(B + 1, 0);
    for (u128 v : vals) {
        ++head[lowbits(v, mask)];
    }
    uint32_t sum = 0;
    for (uint32_t i = 0; i < B; ++i) {
        uint32_t c = head[i];
        head[i] = sum;
        sum += c;
    }
    head[B] = sum;
    idx.resize(vals.size());
    std::vector<uint32_t> cur(head.begin(), head.end());
    for (uint32_t i = 0; i < vals.size(); ++i) {
        idx[cur[lowbits(vals[i], mask)]++] = i;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <p> [L] [t]\n";
        return 1;
    }
    u128 p = parse_u128(argv[1]);
    u128 n = p - 1;
    uint32_t L = (argc >= 3) ? static_cast<uint32_t>(std::stoul(argv[2])) : 12000000u;
    uint32_t t = (argc >= 4) ? static_cast<uint32_t>(std::stoul(argv[3])) : 24u;
    uint32_t B = 1u << t;
    uint32_t mask = B - 1;

    auto t0 = std::chrono::steady_clock::now();
    std::cerr << "[*] p=" << u128_to_string(p) << " L=" << L << " t=" << t << "\n";

    std::vector<u128> bvals, cvals;
    std::cerr << "[*] hashing B/C\n";
    fill_residues(1, L, n, bvals);
    fill_residues(2, L, n, cvals);

    std::cerr << "[*] bucketing C\n";
    std::vector<uint32_t> chead, cidx;
    build_bucket_index(cvals, t, chead, cidx);

    std::cerr << "[*] building right list\n";
    std::vector<RightEntry> right;
    right.reserve(L + L / 4);
    for (uint32_t ib = 0; ib < L; ++ib) {
        u128 eb = bvals[ib];

        uint32_t want0 = static_cast<uint32_t>((B - lowbits(eb, mask)) & mask);
        for (uint32_t pos = chead[want0]; pos < chead[want0 + 1]; ++pos) {
            uint32_t ic = cidx[pos];
            u128 s = eb + cvals[ic];
            if ((static_cast<uint64_t>(s) & mask) == 0) {
                uint64_t q = static_cast<uint64_t>(s >> t);
                uint64_t meta = uint64_t(ib) | (uint64_t(ic) << 24);
                right.push_back({q, meta});
            }
        }

        uint32_t want1 = static_cast<uint32_t>((static_cast<uint64_t>(n) - lowbits(eb, mask)) & mask);
        for (uint32_t pos = chead[want1]; pos < chead[want1 + 1]; ++pos) {
            uint32_t ic = cidx[pos];
            u128 s = eb + cvals[ic];
            if (s >= n) {
                u128 z = s - n;
                if ((static_cast<uint64_t>(z) & mask) == 0) {
                    uint64_t q = static_cast<uint64_t>(z >> t);
                    uint64_t meta = uint64_t(ib) | (uint64_t(ic) << 24) | (1ull << 48);
                    right.push_back({q, meta});
                }
            }
        }
    }
    std::cerr << "[*] right size=" << right.size() << "\n";

    cvals.clear();
    cvals.shrink_to_fit();
    chead.clear();
    chead.shrink_to_fit();
    cidx.clear();
    cidx.shrink_to_fit();

    std::cerr << "[*] sorting right list\n";
    std::sort(right.begin(), right.end(), [](const RightEntry& a, const RightEntry& b) {
        if (a.q != b.q) return a.q < b.q;
        return a.meta < b.meta;
    });

    std::vector<u128> dvals;
    std::cerr << "[*] hashing D\n";
    fill_residues(3, L, n, dvals);

    std::cerr << "[*] bucketing D\n";
    std::vector<uint32_t> dhead, didx;
    build_bucket_index(dvals, t, dhead, didx);

    auto lower_q = [&](uint64_t q) {
        return std::lower_bound(right.begin(), right.end(), q, [](const RightEntry& e, uint64_t val) {
            return e.q < val;
        });
    };

    std::cerr << "[*] scanning A against right list\n";
    for (uint32_t ia = 0; ia < L; ++ia) {
        u128 ea = sha256_mod_u128(make_msg(0, ia), n);

        uint32_t want0 = static_cast<uint32_t>((B - lowbits(ea, mask)) & mask);
        for (uint32_t pos = dhead[want0]; pos < dhead[want0 + 1]; ++pos) {
            uint32_t id = didx[pos];
            u128 s = ea + dvals[id];
            if ((static_cast<uint64_t>(s) & mask) != 0) continue;
            uint64_t q = static_cast<uint64_t>(s >> t);
            auto it = lower_q(q);
            while (it != right.end() && it->q == q) {
                uint32_t ib = static_cast<uint32_t>(it->meta & ((1ull << 24) - 1));
                uint32_t ic = static_cast<uint32_t>((it->meta >> 24) & ((1ull << 24) - 1));
                u128 eb = bvals[ib];
                u128 ec = sha256_mod_u128(make_msg(2, ic), n);
                u128 rhs = eb + ec;
                if ((it->meta >> 48) & 1) rhs -= n;
                if (s == rhs) {
                    u128 cshift = (eb >= ea) ? (eb - ea) : (eb + n - ea);
                    if (gcd_u128(cshift, n) != 1) {
                        ++it;
                        continue;
                    }
                    auto t1 = std::chrono::steady_clock::now();
                    std::cerr << "[*] found in " << std::chrono::duration<double>(t1 - t0).count() << " sec\n";
                    std::cout << hex_msg(make_msg(0, ia)) << "\n";
                    std::cout << hex_msg(make_msg(2, ic)) << "\n";
                    std::cout << hex_msg(make_msg(1, ib)) << "\n";
                    std::cout << hex_msg(make_msg(3, id)) << "\n";
                    std::cout << u128_to_string(cshift) << "\n";
                    return 0;
                }
                ++it;
            }
        }

        uint32_t want1 = static_cast<uint32_t>((static_cast<uint64_t>(n) - lowbits(ea, mask)) & mask);
        for (uint32_t pos = dhead[want1]; pos < dhead[want1 + 1]; ++pos) {
            uint32_t id = didx[pos];
            u128 s = ea + dvals[id];
            if (s < n) continue;
            u128 z = s - n;
            if ((static_cast<uint64_t>(z) & mask) != 0) continue;
            uint64_t q = static_cast<uint64_t>(z >> t);
            auto it = lower_q(q);
            while (it != right.end() && it->q == q) {
                uint32_t ib = static_cast<uint32_t>(it->meta & ((1ull << 24) - 1));
                uint32_t ic = static_cast<uint32_t>((it->meta >> 24) & ((1ull << 24) - 1));
                u128 eb = bvals[ib];
                u128 ec = sha256_mod_u128(make_msg(2, ic), n);
                u128 rhs = eb + ec;
                if ((it->meta >> 48) & 1) rhs -= n;
                if (z == rhs) {
                    u128 cshift = (eb >= ea) ? (eb - ea) : (eb + n - ea);
                    if (gcd_u128(cshift, n) != 1) {
                        ++it;
                        continue;
                    }
                    auto t1 = std::chrono::steady_clock::now();
                    std::cerr << "[*] found in " << std::chrono::duration<double>(t1 - t0).count() << " sec\n";
                    std::cout << hex_msg(make_msg(0, ia)) << "\n";
                    std::cout << hex_msg(make_msg(2, ic)) << "\n";
                    std::cout << hex_msg(make_msg(1, ib)) << "\n";
                    std::cout << hex_msg(make_msg(3, id)) << "\n";
                    std::cout << u128_to_string(cshift) << "\n";
                    return 0;
                }
                ++it;
            }
        }
    }

    std::cerr << "[!] no relation found\n";
    return 2;
}
```

## Solver 2: find_relation.py

This is the small wrapper I used to retry the search with stronger parameters on unlucky rounds.

```python
#!/usr/bin/env python3
import subprocess
import sys


CONFIGS = [
    (12000000, 24),
    (16000000, 24),
    (16000000, 23),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <p>", file=sys.stderr)
        return 1

    p = sys.argv[1]
    for L, t in CONFIGS:
        proc = subprocess.run(
            ["./relation_search", p, str(L), str(t)],
            text=True,
            capture_output=True,
        )
        sys.stderr.write(proc.stderr)
        if proc.returncode == 0:
            sys.stdout.write(proc.stdout)
            return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
```

## Solver 3: Remote solver

This is the full remote solver that ties everything together.

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import socket
import subprocess
import sys


def run_relation_search(p: int) -> tuple[str, str, str, str, int]:
    out = subprocess.check_output(["python3", "find_relation.py", str(p)], text=True)
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    if len(lines) != 5:
        raise RuntimeError(f"unexpected relation_search output: {lines!r}")
    m_a, m_c, m_b, m_d, c = lines
    return m_a, m_c, m_b, m_d, int(c)


def recover_x(p: int, r1: int, r2: int, c: int) -> int:
    n = p - 1
    xc = (r2 * pow(r1, -1, p)) % p
    return pow(xc, pow(c, -1, n), p)


class Tube:
    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port))
        self.buf = b""

    def close(self) -> None:
        self.sock.close()

    def sendline(self, data: str) -> None:
        self.sock.sendall(data.encode() + b"\n")

    def recv_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                out = self.buf
                self.buf = b""
                return out
            self.buf += chunk
        idx = self.buf.index(marker) + len(marker)
        out = self.buf[:idx]
        self.buf = self.buf[idx:]
        return out

    def recv_all(self) -> bytes:
        chunks = [self.buf]
        self.buf = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)


def parse_p(blob: bytes) -> int:
    m = re.search(rb"p=(\d+)", blob)
    if not m:
        raise RuntimeError(f"could not parse p from: {blob!r}")
    return int(m.group(1))


def parse_res(blob: bytes) -> int:
    m = re.search(rb"res=(\d+)", blob)
    if not m:
        raise RuntimeError(f"could not parse res from: {blob!r}")
    return int(m.group(1))


def main() -> int:
    parser = argparse.ArgumentParser(description="Solve the upCTF oracle challenge remotely.")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    tube = Tube(args.host, args.port)
    try:
        banner = tube.recv_until(b"m1=")
        p = parse_p(banner)

        for rnd in range(10):
            print(f"[*] round {rnd + 1}/10 p={p}", file=sys.stderr)
            m_a, m_c, m_b, m_d, c = run_relation_search(p)

            tube.sendline(m_a)
            tube.recv_until(b"m2=")
            tube.sendline(m_c)
            r1 = parse_res(tube.recv_until(b"m1="))

            tube.sendline(m_b)
            tube.recv_until(b"m2=")
            tube.sendline(m_d)
            r2 = parse_res(tube.recv_until(b"m1="))

            x = recover_x(p, r1, r2, c)
            tube.sendline("Stop")
            tube.recv_until(b"x=")
            tube.sendline(str(x))

            if rnd == 9:
                final = tube.recv_all().decode(errors="replace")
                sys.stdout.write(final)
                return 0

            nxt = tube.recv_until(b"m1=")
            p = parse_p(nxt)

        return 0
    finally:
        tube.close()


if __name__ == "__main__":
    raise SystemExit(main())
```

## Final note

The intended lesson here is that the exact-collision approach is not the right lens.

Once I rewrote the problem as:

`e_a + e_d = e_b + e_c mod (p-1)`

the challenge stopped being a plain birthday search and became a generalized birthday problem.

At that point, Wagner's algorithm was exactly the right hammer.
