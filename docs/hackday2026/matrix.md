---
tags:
  - misc
  - stego
  - hackday2026
---

# Matrix Challenge — Steganography

**Category:** Misc / Steganography

## Challenge summary
- Image: The Matrix “bullet time” scene with a cyan waveform overlay and a SHA1 of `4bbab076a0aa488761cd216a82bf4e508a2953ab` to verify the file.
- Hints referenced the “red pill,” “red signals,” LSBs, regrouping bits into bytes, and the Answer to the Ultimate Question (42).
- My key observation was to focus on the red channel’s least significant bits, rebuild bytes, then XOR with `0x42` to undo the distortion.

## Solution outline
1. I extracted the red channel from the PNG and kept only the least significant bit of every pixel (LSB steganography).
2. I flattened the LSB bitstream and grouped it into bytes (8 bits, MSB first) to reconstruct the hidden data.
3. I XORed every byte with `0x42` (the hexadecimal representation of “42” from Hitchhiker’s Guide) to remove the obfuscation.
4. I searched the result for `HACKDAY{...}` and printed the flag.

## Key implementation
```python
from PIL import Image
import numpy as np

img = Image.open('Matrix_challenge.png')
red = np.array(img)[:, :, 0]
flat_lsb = (red & 1).flatten()

bytes_out = []
for i in range(0, len(flat_lsb) - 8, 8):
    byte = 0
    for bit in range(8):
        byte = (byte << 1) | flat_lsb[i + bit]
    bytes_out.append(byte)

decoded = bytes(b ^ 0x42 for b in bytes_out)
flag_start = decoded.find(b'HACKDAY{')
flag_end = decoded.find(b'}', flag_start)
print(decoded[flag_start:flag_end + 1].decode())
```

## Result
- Flag: `HACKDAY{e3a12b9383038b0c6d755bcb39d3bf879cac3750588226ba1c52d64fde0a7c96}`
