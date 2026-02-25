# Hackena CTF - LWE Lattice Challenge Writeup

## Challenge Overview

I was given a Python script (`chall.py`) that implements a lattice-based cryptographic scheme and an output file containing the public parameters and encrypted flag.

## Analysis

### Understanding the Scheme

The challenge constructs the following:

1. **Secret generation**: A small vector `z ∈ {-1, 0, 1}^n` is generated
2. **Lattice basis `Bs`**: A special structured matrix of the form:
   ```
   Bs = [ q·I_k  |    0    ]
        [   X    | I_{n-k} ]
   ```
   where `k = 12`, `n = 40`, and `q = 12289`

3. **Secret `s`**: Computed as `s = z · Bs (mod q)`
4. **LWE instance**: `b = s·A + e (mod q)` where `e ∈ {-1, 0, 1}^m` is small error
5. **Encryption**: The flag is XOR'd with `SHA256(s)`

### Key Parameters
- `q = 12289` (prime modulus)
- `n = 40` (secret dimension)
- `k = 12` (identity block size)
- `m = 60` (LWE sample dimension)

## Solution Strategy

The goal is to recover `s` to derive the decryption key. Since `s = z·Bs` where `z` is small, this is a **bounded distance decoding (BDD)** problem that can be solved using lattice reduction.

### Kannan's Embedding Technique

I constructed a lattice that encodes both constraints:
1. `s = z·Bs` (s lies in the Bs lattice)
2. `b = s·A + e` (LWE relation with small error)

Substituting, I got: `z·(Bs·A) + e ≡ b (mod q)`

I built the embedding lattice:

```
L = [ q·I_m   |    0    |  0 ]
    [ (Bs·A)ᵀ |  c·I_n  |  0 ]
    [    b    |    0    |  W ]
```

Where:
- `c` is a scaling factor for the `z` components
- `W` is the embedding weight to identify the target vector

A short vector in this lattice corresponds to `(e, c·z, W)` where both `e` and `z` are small.

## Implementation

```python
import json
import hashlib
from fpylll import IntegerMatrix, BKZ

# Load data
with open("output.txt", "r") as f:
    data = json.load(f)

q, A, b, Bs = data["q"], data["A"], data["b"], data["Bs"]
enc_flag = bytes.fromhex(data["enc_flag_hex"])
n, m = len(Bs), len(A[0])

# Compute Bs * A (mod q)
BsA = [[sum(Bs[i][k] * A[k][j] for k in range(n)) % q 
        for j in range(m)] for i in range(n)]

# Build embedding lattice
W, Z_scale = 100, 10
dim = m + n + 1
L = IntegerMatrix(dim, dim)

# Fill lattice blocks
for i in range(m):
    L[i, i] = q
for j in range(n):
    for i in range(m):
        L[m + j, i] = BsA[j][i]
    L[m + j, m + j] = Z_scale
for i in range(m):
    L[m + n, i] = b[i]
L[m + n, m + n] = W

# Run BKZ reduction
BKZ.reduction(L, BKZ.Param(30))

# Search for solution
for i in range(dim):
    row = [L[i, j] for j in range(dim)]
    if abs(row[-1]) != W:
        continue
    
    sign = 1 if row[-1] == W else -1
    z = [sign * row[m + j] // Z_scale for j in range(n)]
    
    if max(abs(x) for x in z) > 1:
        continue
    
    # Try both z and -z
    for z_try in [z, [-x for x in z]]:
        s = [sum(z_try[j] * Bs[j][i] for j in range(n)) % q for i in range(n)]
        sA = [sum(s[i] * A[i][j] for i in range(n)) % q for j in range(m)]
        e = [(b[j] - sA[j]) % q for j in range(m)]
        e_norm = [x if x <= q//2 else x - q for x in e]
        
        if max(abs(x) for x in e_norm) <= 1:
            # Decrypt flag
            key = hashlib.sha256(b"".join(
                int(s[i]).to_bytes(2, "little") for i in range(n)
            )).digest()
            flag = bytes(enc_flag[i] ^ key[i % len(key)] 
                        for i in range(len(enc_flag)))
            print(f"Flag: {flag.decode()}")
```

## Flag

```
Hackena{In_Th3_Re4lm_0f_LLL_JUST_RAAAAAAAAAAAAAAAAAAA}
```
