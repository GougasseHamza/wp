---
tags:
  - midnightctf
  - web
  - misc
  - pwn
---

# MidnightFlag CTF

MidnightFlag CTF had one challenge that was worth documenting twice: once for the initial account-takeover path, and once for the full follow-up chain that pushed the Node bot all the way to root-level flag retrieval.

## What I published

- [Mineslayer](mineslayer.md) covers the original solve path, the nick-formatting bug, the predictable password reset flow, and the first flag.
- [Mineslayer — Flag 2](mineslayer-flag2.md) covers the full `/bot` JSON injection and prototype-pollution chain that led to `/getflag`.

## Main themes

- chat rendering and parsing mismatches
- privileged bot abuse
- predictable password generation
- JSON injection into a bot config
- prototype pollution reaching a code-generation gadget

The two pages are separate because the second one is really a follow-up exploitation writeup, not just an appendix.
