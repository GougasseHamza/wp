# SwitchCaseAdvocate (Fortune Teller's Revenge)

Target: `nc chall.0xfun.org 42891`

I observed the service print three 32-bit "glimpses" (the upper 32 bits) of a 64-bit RNG state, with a large "jump across time" between glimpses, then ask for the next 5 full 64-bit states.

## Given RNG

From the provided script (`fortune_revenge(1).py`), I saw the Fortune Teller use a 64-bit LCG:

```text
M = 2^64
state <- (A * state + C) mod M
```

and a precomputed skip-ahead ("jump"):

```text
state <- (A_JUMP * state + C_JUMP) mod M
```

The "glimpse" is:

```text
full = next()
return full >> 32
```

So the server's three printed values are:

```text
g1 = s1 >> 32, where s1 = next(seed)
g2 = s2 >> 32, where s2 = next(jump(s1))
g3 = s3 >> 32, where s3 = next(jump(s2))
```

Constants:

```text
A = 2862933555777941757
C = 3037000493
JUMP = 100000
A_JUMP = A^JUMP mod 2^64
C_JUMP = 8391006422427229792
```

## Collapse "jump + next" into one LCG step

Let:

```text
f(s) = (A * s + C) mod 2^64          (next)
j(s) = (A_JUMP * s + C_JUMP) mod 2^64 (jump)
```

One observed transition is `s -> f(j(s))`, which is still affine:

```text
f(j(s)) = A*(A_JUMP*s + C_JUMP) + C
        = (A*A_JUMP)*s + (A*C_JUMP + C)      (mod 2^64)
```

Define the combined constants:

```text
P = (A * A_JUMP) mod 2^64
Q = (A * C_JUMP + C) mod 2^64
```

For this challenge:

```text
P = 8810128861561192317
Q = 1496106642115246093
```

So the full (hidden) 64-bit states satisfy:

```text
s2 = (P*s1 + Q) mod 2^64
s3 = (P*s2 + Q) mod 2^64
```

and the server reveals only:

```text
g1 = s1 >> 32
g2 = s2 >> 32
g3 = s3 >> 32
```

## Recover the full 64-bit state with a 2^32 brute force (fast)

Write:

```text
s1 = (g1 << 32) | x
```

where `x` is the unknown lower 32 bits.

Then:

```text
s2(x) = (P*s1 + Q) mod 2^64
      = (P*(g1<<32) + Q) + P*x       (mod 2^64)
```

Let `base = (P*(g1<<32) + Q) mod 2^64`. Instead of recomputing the multiply each time, iterate:

```text
s2(0) = base
s2(x+1) = (s2(x) + P) mod 2^64
```

For each `x` in `[0, 2^32)`:

1. Check if `s2(x) >> 32 == g2`.
2. If yes, compute `s3 = (P*s2(x) + Q) mod 2^64` and check `s3 >> 32 == g3`.

Because matching a random 32-bit prefix happens with probability `1/2^32`, you expect about one `g2` hit in the entire loop, so only ~one expensive multiply is needed.

Once `x` is found, you have the exact `s1, s2, s3`.

## Predict the next 5 full 64-bit states

After the third glimpse, the challenge asks for the "next 5 full 64-bit states".

Those are the next outputs of the original `next()` LCG (multiplier `A`, increment `C`) starting from the recovered `s3`:

```text
repeat 5 times:
  s <- (A*s + C) mod 2^64
  print s
```

## Exploit

### `bf_solver.c` (recovers `s1 s2 s3` from `g1 g2 g3`)

```c
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "usage: %s g1 g2 g3\n", argv[0]);
    return 2;
  }

  uint32_t g1 = (uint32_t)strtoul(argv[1], NULL, 10);
  uint32_t g2 = (uint32_t)strtoul(argv[2], NULL, 10);
  uint32_t g3 = (uint32_t)strtoul(argv[3], NULL, 10);

  // Combined step constants for s' = P*s + Q (mod 2^64), where s' = next(jump(s)).
  const uint64_t P = 8810128861561192317ull;
  const uint64_t Q = 1496106642115246093ull;

  uint64_t s1_hi = ((uint64_t)g1) << 32;

  // s2(x) = P*(s1_hi + x) + Q = (P*s1_hi + Q) + P*x (mod 2^64)
  uint64_t s2 = P * s1_hi + Q; // x=0

  uint64_t found_x = UINT64_MAX;
  uint64_t found_s3 = 0;

  for (uint64_t x = 0; x < (1ull << 32); x++) {
    if ((uint32_t)(s2 >> 32) == g2) {
      uint64_t s3 = P * s2 + Q;
      if ((uint32_t)(s3 >> 32) == g3) {
        found_x = x;
        found_s3 = s3;
        break;
      }
    }
    s2 += P;
  }

  if (found_x == UINT64_MAX) {
    fprintf(stderr, "no solution found\n");
    return 1;
  }

  uint64_t s1 = s1_hi | (uint32_t)found_x;
  uint64_t s2_sol = P * s1 + Q;
  printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n", s1, s2_sol, found_s3);
  return 0;
}
```

Build:

```bash
gcc -O3 -march=native bf_solver.c -o bf_solver
```

### `solve_switchcase.py` (gets flag)

```python
#!/usr/bin/env python3
import socket
import subprocess

HOST = "chall.0xfun.org"
PORT = 42891

MASK = (1 << 64) - 1

# Original LCG constants (next())
A = 2862933555777941757
C = 3037000493

def recv_until(sock: socket.socket, token: bytes) -> bytes:
    buf = b""
    while token not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

def parse_prompt(data: bytes):
    text = data.decode(errors="replace")
    nums = []
    for ln in text.splitlines():
        ln = ln.strip()
        if ln.isdigit():
            nums.append(int(ln))
    if len(nums) < 3:
        raise ValueError(f"could not parse 3 numbers: {text!r}")
    return nums[0], nums[1], nums[2], text

def lcg_next(x: int) -> int:
    return (A * x + C) & MASK

def main():
    with socket.create_connection((HOST, PORT), timeout=5) as s:
        data = recv_until(s, b":")
        g1, g2, g3, banner = parse_prompt(data)
        s1, s2, s3 = map(int, subprocess.check_output(
            ["./bf_solver", str(g1), str(g2), str(g3)], text=True
        ).split())

        # Predict next 5 *next()* states starting from s3.
        preds = []
        cur = s3
        for _ in range(5):
            cur = lcg_next(cur)
            preds.append(cur)

        s.sendall((" ".join(map(str, preds)) + "\n").encode())
        print(banner, end="")
        print(s.recv(4096).decode(errors="replace"), end="")

if __name__ == "__main__":
    main()
```

## Flag

`0xfun{r3v3ng3_0f_th3_f0rtun3_t3ll3r}`
