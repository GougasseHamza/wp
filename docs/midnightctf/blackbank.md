---
tags:
  - midnightctf
  - web
  - crypto
---

# BlackBank

**Flag:** `MCTF{v8_1s_n0t_SEcur3_4t_4l7}`

## Overview

BlackBank exposed two related apps: a bank panel and a matching mail system. The challenge gave me access to a low-level member account, but the flag only appeared on the boss account's dashboard.

What made this challenge interesting is that I did not get the solve by chaining normal web bugs all the way through. I spent a long time trying to break the application layer first, got nowhere, stepped away, and came back with a different question:

> if I cannot force the app to skip 2FA, can I predict the next 2FA code instead?

That turned out to be the real path.

The final chain was:

1. exploit SQL injection in the bank login
2. extract the boss credentials and 2FA mail routing
3. fail to land any practical web-app-side 2FA bypass
4. notice the stack is Express, so the randomness is likely coming from Node and V8
5. collect enough 2FA codes from my own account
6. recover the V8 `Math.random()` state
7. predict the next boss 2FA code and log in as `Vladizlow`

## Step 1: Extract the boss credentials

The bank login accepted SQL injection in the `username` field. Union probing showed the query expected four columns, and blind extraction revealed the backing table:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    emailUser TEXT NOT NULL
)
```

The interesting rows were:

| id | username | password | emailUser |
|----|----------|----------|-----------|
| 1 | katarina | Kathax0r_sk1d0s | katarina |
| 2 | Vladizlow | xeAgQ8dJcc0hUVCm2EV9 | admin |

That immediately explained why the challenge was not solved after dumping the password. `Vladizlow` did not receive 2FA codes in the same mailbox as the low-privilege account.

## Step 2: Everything I tried on the web app first

After getting `Vladizlow`'s password, I assumed the rest of the solve would still be in the web layer. I tried basically every angle that looked remotely plausible:

- broken access control on the bank and mail routes
- response manipulation and parameter tampering around `/bank/2fa`, `/bank/resend`, and `/bank/profile`
- IDOR-style pivots around anything user-linked in bank or mail flows
- race conditions during login, resend, and 2FA verification
- second-order SQLi ideas, especially anything that might poison `emailUser` or change where the code was delivered
- session confusion, like validating one user then swapping to another
- brute-forcing the admin mailbox and other obvious credential guesses

None of it worked.

That was the turning point. I had real credentials for the boss account, but the web app would not give me the second factor no matter how I poked at it. So I stopped asking "how do I bypass this page?" and started asking "how is this code generated?"

The first clue was the stack. The app looked like Express, which strongly suggested Node.js on the backend. Once I was thinking in Node terms, the next thought was obvious: if they used weak randomness for the 2FA code, then that randomness probably comes from V8.

The second clue was the shape of the codes themselves. They looked exactly like:

```javascript
Math.floor(Math.random() * 100000000)
```

That was the moment the challenge stopped looking like a pure web exploit and started looking like a runtime / PRNG problem.

## Step 3: Why Express led me to V8 `Math.random()`

Express meant Node, and Node meant V8. If the developer had used the lazy option for code generation, there was a good chance the 2FA values came from `Math.random()` rather than a cryptographic API like `crypto.randomInt()`.

Once I started treating the 2FA code as a PRNG output instead of a web token, the rest of the path made sense:

- I could generate more codes for my own account with `/bank/resend`
- those codes gave me observations from the same backend RNG
- if the implementation was really V8 `Math.random()`, then I could try recovering the generator state and predicting the next output for `Vladizlow`

Node's `Math.random()` is powered by V8's xorshift128+ generator. For performance, V8 fills a 64-value cache and serves the numbers in LIFO order, which means the observed outputs have to be reversed before feeding them into a forward solver.

That mattered for two reasons:

- `Math.random()` is not suitable for security-sensitive values like 2FA codes
- observing a small batch of outputs from one cache segment is enough to recover the 128-bit internal state

In this challenge, around ten consecutive codes from a single session were enough to recover a unique state candidate with a Z3-based model.

## Step 4: Collect codes from a single session

The important operational detail was keeping all observed codes inside one cache segment. I used one mail session to read the inbox, and one bank session to repeatedly trigger resend:

```python
import requests, re, sys, time

BASE = sys.argv[1]

mail = requests.Session()
mail.post(f"{BASE}/mail/login", data={
    "username": "katarina",
    "password": "Kathax0r_sk1d0s",
})

bank = requests.Session()
bank.post(f"{BASE}/bank/login", data={
    "username": "katarina",
    "password": "Kathax0r_sk1d0s",
})

codes = []
for _ in range(10):
    bank.post(f"{BASE}/bank/resend")
    time.sleep(0.3)
    seen = re.findall(r'⚡ (\d+)', mail.get(f"{BASE}/mail/inbox").text)
    if seen and (not codes or seen[0] != codes[-1]):
        codes.append(seen[0])

print(codes)
```

A sample batch looked like:

```text
19368238, 13611877, 24411298, 66357597, 25991259,
85264482, 63657524, 43659187, 70329421, 80332196
```

## Step 5: Recover the state and predict the next code

Feeding those observations into a V8 xorshift128+ model produced a single candidate state and a short list of future outputs. The next relevant prediction was:

```text
67610404
```

The key modeling detail was accounting for both:

- the `Math.floor(100000000 * x)` truncation
- the reversed output order caused by the 64-value LIFO cache

Without the cache reversal, the constraints do not line up with V8's real output stream.

## Step 6: Log in as the boss

Once I had `Vladizlow`'s password from SQLi and the next 2FA prediction from the solver, the last step was just a normal login:

```python
import requests, re, sys

BASE = sys.argv[1]

boss = requests.Session()
boss.post(f"{BASE}/bank/login", data={
    "username": "Vladizlow",
    "password": "xeAgQ8dJcc0hUVCm2EV9",
})

boss.post(f"{BASE}/bank/2fa", data={"code": "67610404"})
profile = boss.get(f"{BASE}/bank/profile").text
print(re.findall(r'MCTF\\{[^}]+\\}', profile)[0])
```

That redirected to the boss dashboard and revealed:

```text
MCTF{v8_1s_n0t_SEcur3_4t_4l7}
```

## Full chain

1. Use SQLi on `/bank/login` to dump the `users` table.
2. Recover `Vladizlow`'s password and the fact that his codes are routed to the `admin` mailbox.
3. Try the normal web-app routes first: BAC, response manipulation, IDOR ideas, race conditions, second-order SQLi, and admin brute-force.
4. Conclude that the app layer is not giving a practical bypass.
5. Notice the backend is Express, infer Node/V8, and pivot to the RNG behind the 2FA codes.
6. Log in as `katarina` and collect consecutive 2FA codes from one bank session.
7. Recover the V8 xorshift128+ state from those observed codes.
8. Predict the next valid boss 2FA code.
9. Log in as `Vladizlow`, submit the predicted code, and read the flag from `/bank/profile`.

## Takeaways

- `Math.random()` should never be used for authentication or 2FA.
- Output caching details matter just as much as the PRNG itself when you are modeling a real implementation.
- SQLi only got me to the interesting part. The actual solve came from recognizing that the web app was not budging and shifting the attack to the runtime's randomness instead.
