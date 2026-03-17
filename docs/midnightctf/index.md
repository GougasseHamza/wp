---
tags:
  - midnightctf
  - web
  - crypto
---

# MidnightFlag CTF

MidnightFlag CTF currently has two published challenge lines here: BlackBank, and the two-part Mineslayer writeup set.

## What I published

- [BlackBank](blackbank.md) covers the bank login SQLi, the weak `Math.random()`-based 2FA flow, and the V8 state-recovery path that predicts the boss account's next code.
- [Mineslayer](mineslayer.md) covers the original solve path, the nick-formatting bug, the predictable password reset flow, and the first flag.
- [Mineslayer — Flag 2](mineslayer-flag2.md) covers the full `/bot` JSON injection and prototype-pollution chain that led to `/getflag`.

## Main themes

- predictable 2FA
- V8 `Math.random()` state recovery
- chat rendering and parsing mismatches
- privileged bot abuse
- predictable password generation
- JSON injection into a bot config
- prototype pollution reaching a code-generation gadget
