# ASIS CTF

ASIS CTF is one of those competitions that makes you think differently about security. Run by the Academy for Skills and Information Security team, it's known for creative challenges that go beyond the typical "find the SQL injection" problems. When I decided to tackle some of their web challenges, I knew I was in for a learning experience.

## What I Worked On

I focused on the web exploitation category, where I found four challenges that each taught me something different about breaking web applications. Some were straightforward, others had me stuck for hours. But that's exactly what makes these competitions valuable - they force you to dig deeper.

### The Challenges

#### [Sanchess](sanchess.md)

This was a Rick and Morty themed chess game that looked innocent at first. You could program Rick's moves to reach Morty on a chess board. I quickly discovered it was vulnerable to Python expression injection - I could make the server evaluate arbitrary Python code through the move conditions.

The interesting part came when the challenge got patched mid-competition. The organizers added filters to block keywords like "open" and "read". I had to learn about Unicode normalization bypasses, using fullwidth characters that look different but evaluate the same way. It was my first time exploiting Unicode normalization, and it completely changed how I think about filter evasion.

[Read the full writeup](sanchess.md)

---

#### [Rick Gallery](rick-gallery.md)

An image gallery application that seemed simple enough. It had filters to prevent accessing dangerous PHP wrappers like `php://` and `file://`. The vulnerability? The filters only checked for lowercase versions of these wrappers.

PHP's stream wrappers are case-insensitive, so `PHP://` and `FILE://` worked perfectly while bypassing all the filters. Sometimes the most effective exploits are the simplest ones. I used this to read arbitrary files on the system and eventually found the flag in `/tmp/flag.txt`.

[Read the full writeup](rick-gallery.md)

---

#### [ASIS Mail](asis-mail.md)

This was a microservices-based email application with an API, SSO service, object storage, and nginx frontend. The attack surface was large, and I had to chain multiple vulnerabilities to reach the flag.

First, I found SSRF in the email composition endpoint. Then I discovered path traversal in the object storage service - it checked if the bucket name was "FLAG" but didn't sanitize the path itself. By using my own bucket with `../` to traverse to the FLAG directory, I could read protected files.

The clever part was discovering the flag filename by exploiting an IDOR vulnerability to read other users' emails. I could see what filenames other competitors had tried, which led me to the correct flag filename.

[Read the full writeup](asis-mail.md)

---

#### [Bookmarks](bookmarks.md)

This was the hardest one. A Flask bookmark manager that inserted the username directly into HTTP response headers. If the username contained CRLF characters (`\r\n`), I could inject my own headers and even inject content into the response body.

The breakthrough came when I realized I could push the Content-Security-Policy header into the response body by ending the headers early with `\r\n\r\n`. This meant CSP wasn't enforced, and I could execute arbitrary JavaScript.

The timing was tricky - I had to open a popup window that would load my injected script, wait for the bot to log in as the flag user, then use `fetch()` to read the dashboard using the shared session cookie. It took several attempts to get the timing right.

[Read the full writeup](bookmarks.md)

---

*These writeups document my learning process and are shared for educational purposes.*
