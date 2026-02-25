# Fortune Teller - LCG Truncated Output Attack

**Flag:** `0xfun{trunc4t3d_lcg_f4lls_t0_lll}`

## Challenge

We're given a Python script implementing a Linear Congruential Generator (LCG):

```python
class FortuneTeller:
    def __init__(self, seed=None):
        self.M = 2**64
        self.A = 2862933555777941757
        self.C = 3037000493
        self.state = seed if seed is not None else random.randint(1, self.M - 1)

    def next(self):
        self.state = (self.A * self.state + self.C) % self.M
        return self.state

    def glimpse(self):
        full = self.next()
        return full >> 32
```

The server gives us 3 "glimpses" (upper 32 bits of consecutive states) and asks us to predict the next 5 **full 64-bit states**.

## Analysis

The LCG follows the recurrence:
```
state_{n+1} = (A * state_n + C) mod M
```

Where:
- M = 2^64
- A = 2862933555777941757
- C = 3037000493

The `glimpse()` function only reveals the upper 32 bits: `state >> 32`

This is a classic **truncated LCG** problem. We observe high bits but need to recover the full state.

## The Math

Let B = 2^32. For each state:
```
state_i = g_i * B + x_i    where 0 ≤ x_i < B
```

Here `g_i` is the known glimpse and `x_i` is the unknown lower 32 bits.

From the LCG relation:
```
state_2 = A * state_1 + C  (mod M)
g_2 * B + x_2 = A * (g_1 * B + x_1) + C  (mod M)
```

Rearranging:
```
A * x_1 - x_2 ≡ g_2 * B - A * g_1 * B - C  (mod M)
A * x_1 - x_2 ≡ D_1  (mod M)
```

Where D_1 is a known constant. This gives us:
```
A * x_1 = D_1 + x_2 + k * M    for some integer k
```

## Solving the Constraints

Since both x_1 and x_2 must be in [0, B), and A is known, we can:

1. Determine valid values of k (only a few possibilities)
2. For each k, find x_2 values where (D_1 + x_2 + k*M) is divisible by A
3. Check if the resulting x_1 = (D_1 + x_2 + k*M) / A is in [0, B)
4. Verify against the third glimpse

The key insight is that A is large (~2^61), so very few (x_1, x_2) pairs satisfy all constraints. With 3 glimpses, we have enough constraints to uniquely determine the state.

## Solution

```python
from pwn import *

M = 2**64
A = 2862933555777941757  
C = 3037000493
B = 2**32

def next_state(state):
    return (A * state + C) % M

def solve(glimpses):
    g1, g2, g3 = glimpses
    
    T1 = A * g1 * B + C
    D1 = g2 * B - T1
    
    k_min = (-D1 - B + 1) // M - 1
    k_max = (A * B - D1) // M + 1
    
    for k in range(k_min, k_max + 1):
        base = D1 + k * M
        x2_lo = max(0, -base)
        x2_hi = min(B, A * B - base)
        
        if x2_lo >= x2_hi:
            continue
        
        rem = (-base) % A
        first_x2 = rem if rem >= x2_lo else x2_lo + (rem - x2_lo % A) % A
        
        for x2 in range(first_x2, x2_hi, A):
            x1 = (base + x2) // A
            if 0 <= x1 < B:
                s1 = g1 * B + x1
                s2 = next_state(s1)
                if (s2 >> 32) == g2:
                    s3 = next_state(s2)
                    if (s3 >> 32) == g3:
                        return s1
    return None

conn = remote('chall.0xfun.org', 59560)
data = conn.recvuntil(b'separated):').decode()

import re
glimpses = [int(n) for n in re.findall(r'\b\d{8,10}\b', data)[:3]]

state = solve(glimpses)

# Advance past the 3 glimpses we already saw
for _ in range(2):
    state = next_state(state)

# Predict next 5 full states
predictions = []
for _ in range(5):
    state = next_state(state)
    predictions.append(state)

conn.sendline(' '.join(map(str, predictions)).encode())
print(conn.recvall().decode())
```

## Why It Works

The flag hints at **LLL** (Lenstra–Lenstra–Lovász lattice basis reduction), which is the standard cryptographic attack for truncated LCGs. However, for this specific case with only 32 bits hidden and 3 samples, the constraint-based approach is sufficient and faster.

The vulnerability exists because:
1. LCG state transitions are linear
2. Knowing partial output creates a system of modular equations
3. The constraints are tight enough that brute-force over the small solution space is feasible

## Takeaway

Never use truncated LCG output for cryptographic purposes. Even revealing only half the bits allows full state recovery with just a few samples.
