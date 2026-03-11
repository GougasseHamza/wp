# fix - Writeup

I solved this challenge by abusing the internal admin page as a cross-origin query gadget and then pivoting into Solr's `flag` collection through the unsafely concatenated search query.

## Overview

The challenge had three moving parts:

- a public web app on port `5003`
- an internal admin app on port `8080`
- a headless bot that visits attacker-controlled URLs submitted through `/api/report`

At first glance, the intended bug looked straightforward: get the bot to load my page, steal the admin token from `admin.html`, and call the internal admin API with a malicious Solr query. The tricky part was getting that to work in a modern browser from a public origin.

The final solve was:

1. I hosted a public page.
2. That page created a sandboxed helper iframe with `allow-popups`.
3. The helper opened `http://web:8080/admin.html` in a popup.
4. Because the popup inherited the sandbox, its origin serialized as `"null"`.
5. The admin page accepted `postMessage` from that popup because it only compared `event.origin` to `window.origin`, and both were `"null"`.
6. I used the admin page to query Solr with `*:*&shards.info=true` first, discovered the real internal Solr host, then queried the `flag` collection with `*:*&shards=<host>/solr/flag&fl=flag`.
7. I exfiltrated the result back to my server.

## Vulnerability Analysis

### 1. The internal admin page was reachable from the bot

The app exposes `/admin.html` only on the internal port, but the bot browser runs inside the same Docker network, so it can access:

- `http://web:8080/admin.html`

That alone would not be enough, but the page also embeds the admin token in JavaScript.

Relevant file:

- [web/templates/admin.html](/home/kyyblin/Downloads/fix/web/templates/admin.html)

### 2. The admin page trusted `postMessage` from `"null"`

The admin page contained this logic:

```js
window.addEventListener("message", async (event) => {
    if (event.origin !== window.origin) {
        return;
    }
    ...
});
```

That check is weak. If I load the page inside a sandboxed browsing context, the origin becomes opaque and serializes to `"null"`. A second sandboxed context also serializes to `"null"`, so the string comparison passes even though this is not a real same-origin relationship.

This became the core primitive of the final exploit.

### 3. The admin API concatenated `q` directly into the Solr URL

The internal admin endpoint did not safely structure Solr parameters. It took the user-supplied `q` and appended it directly to the backend Solr request. It only blocked the substring `collection`, which was not enough.

Relevant file:

- [web/server.js](/home/kyyblin/Downloads/fix/web/server.js)

That meant I could inject extra Solr parameters inside `q`, for example:

```text
*:*&shards=172.22.0.2:8983/solr/flag&fl=flag
```

### 4. Solr exposed the shard address through `shards.info=true`

Instead of brute-forcing Docker bridge ranges, I first queried:

```text
*:*&shards.info=true
```

The response included the real shard address, so I could derive the exact internal Solr host dynamically and then query the `flag` collection reliably.

This made the exploit much more robust remotely.

## What Did Not Work Reliably

Before landing on the popup route, I tried several variants:

- direct `fetch("http://web:8080/...")` from a public page
- a public page embedding `admin.html` directly in a sandboxed iframe
- HTTPS plus `targetAddressSpace: "local"`
- popup retargeting to a `javascript:` URL

The first three ran into modern Chrome private-network and mixed-content restrictions. The `javascript:` popup retarget idea failed with a `SecurityError`.

The sandboxed popup route was the one that survived both local and public-HTTPS rehearsal.

## Final Exploit Strategy

I ended up serving a page equivalent to [index.html](/home/kyyblin/Downloads/fix/index.html).

The key logic was:

1. Create a hidden sandboxed helper iframe:

```html
<iframe sandbox="allow-scripts allow-popups">
```

2. From inside that helper, call:

```js
window.open("http://web:8080/admin.html", "adm");
```

3. Relay queries from the parent to the popup with `postMessage`.

4. Wait for the popup to answer with:

```js
{ status: "success", data: "..." }
```

5. Parse the first response from `*:*&shards.info=true`, extract the shard host, then send:

```text
*:*&shards=<host>/solr/flag&fl=flag
```

6. Leak the resulting JSON back to my server with an `Image` request.

## Why the Popup Route Worked

The important detail is that I no longer needed a public page to directly fetch a private-network URL. That was the part modern Chrome was blocking.

Instead, I used:

- top-level popup navigation to `http://web:8080/admin.html`
- sandbox inheritance to keep the popup origin opaque
- the admin page's own JavaScript to perform the authenticated internal `fetch`

So I turned the admin page itself into the query gadget.

## Validation

I validated the exploit in three stages:

1. Local bot + private local page
2. Local bot + public HTTPS tunnel
3. Remote bot + public HTTPS tunnel

The second validation mattered the most because it reproduced the public-origin browser conditions that had broken the earlier approaches.

For the public tunnel, I exposed my local exploit server with:

```bash
python3 server.py
ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 nokey@localhost.run
```

Then I submitted the returned HTTPS URL to the report endpoint.

## Reproduction

### Start the exploit server

```bash
python3 server.py
```

### Expose it publicly

```bash
ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 nokey@localhost.run
```

### Submit to the challenge

```bash
curl -X POST 'http://TARGET/api/report' \
  -H 'Content-Type: application/json' \
  --data '{"url":"https://YOUR-TUNNEL.lhr.life/"}'
```

### Expected leak stages

On my server, I expected to see:

- `helper_loaded`
- `popup_open`
- `popup_from_admin`
- `discovered`
- `flag`

## Takeaways

The challenge was not just about spotting a backend query-injection bug. The real difficulty was finding a browser delivery primitive that still worked under current Chrome behavior.

The successful chain combined:

- weak `postMessage` origin validation
- a token embedded in internal HTML
- Solr parameter injection through `q`
- shard discovery through `shards.info=true`
- and a sandboxed popup to preserve the `"null"` origin trick

That combination was enough to turn the internal admin page into an authenticated proxy for reading the hidden `flag` collection.
