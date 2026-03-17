---
tags:
  - midnightctf
  - web
  - misc
  - pwn
---

# Mineslayer

**Flags:** `FLAG_1` solved, `FLAG_2` documented separately in [the full follow-up writeup](mineslayer-flag2.md)

## Challenge Overview

Mineslayer is a Minecraft-based challenge built around a Paper server, a privileged helper bot, and a second bot launched through a vulnerable `/bot` command. The first flag came from abusing how three different components interpreted nicknames and chat messages. The second flag depended on turning the bot configuration bug into real code execution.

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

The important pieces were:

- the nickname filter in the Paper plugin
- the helper bot that reacts to URLs in chat
- the deterministic password reset logic
- the `/bot` command that serializes attacker-controlled input into JSON

## Key Bugs

### 1. Nick filtering only blocked some MiniMessage tags

The plugin stripped a small set of dangerous tags, but color tags were left alone:

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

That meant payloads like `x<c:Administrator>` survived the filter.

### 2. The helper bot trusted parsed chat sender names

When the bot saw a URL, it looked up the sender and then issued a password reset:

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

Because the nick payload rendered differently across the server, SimpleNicks, and the bot's parser, I could make the helper treat my message as if it came from `Administrator`.

### 3. Password resets were predictable

The plugin generated passwords with `java.util.Random` seeded from the world seed:

```java
private static Random getRandom() {
    if (random == null) {
        long seed = Bukkit.getWorld("world").getSeed();
        random = new Random(seed);
    }
    return random;
}
```

Once I forced `/renew Administrator`, the new password was just the next value in a deterministic sequence.

### 4. `/bot` was obviously dangerous

The challenge also exposed a second bug surface through `/bot`: attacker-controlled commands were written into JSON without escaping, and that JSON was later merged into the Node bot config. That path matters for `FLAG_2`, so I cover it in detail on the follow-up page.

## FLAG_1: Admin Account Takeover

The payload that worked most reliably was:

```text
x<c:Administrator>
```

The chain was:

1. Register as a normal user.
2. Set the nick to `x<c:Administrator>`.
3. Send any URL in chat.
4. Let the helper bot misidentify the sender and run `/renew Administrator`.
5. Log in as `Administrator` with the next predicted password.
6. Run `/flag`.

The two critical observations were:

- the nickname filter and the bot did not agree on what the visible sender name was
- the password generator was deterministic enough to predict post-reset credentials

## Predicted Password Sequence

The first few generated values looked like this:

```javascript
const predicted = [
  '1HryYNeloPBLeWyY',
  'T4sPU4pqZH_hR9iu',
  'LLlAlGhSph1AU0Dk',
  'ZTLVc839AyI_qjcJ',
  'MrMFEGGNUMzp3fhS'
]
```

After the forced reset, I just iterated the predicted sequence until the admin login succeeded.

## Result

```text
FLAG_1: MCTF{M1ni_M3ssage_N3st1ng_g0es_H4rd}
FLAG_1 (revenge): MCTF{W1ll_Y0u_F1nd_4n0th3r_Byp4ss??}
```

## Follow-up

The first flag was already a nice multi-component bug chain, but the more interesting bug was still `/bot`. The full `FLAG_2` chain is documented here:

- [Mineslayer — Flag 2](mineslayer-flag2.md)
