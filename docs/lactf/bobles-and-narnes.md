---
tags:
  - web
  - lactf
---

# Bobles and Narnes - First-Person Writeup

**Category:** Web

## Challenge Overview

I analyzed a Bun + Express bookstore app where I started with `$1000`, but the `Flag` item cost `$1,000,000`.
At first glance, that looked impossible to buy directly.

The target behavior was:

1. Add items to cart via `/cart/add`.
2. Checkout via `/cart/checkout`.
3. Receive a ZIP of purchased files.

The key idea was to make the server think the expensive flag item was a sample during the price check, but store it as a full item in the database before checkout.

## Initial Recon

I reviewed the main backend logic in `server.js`.

Important parts I identified:

1. Cart schema stores `is_sample` in `cart_items` (`server.js:40`).
2. Price check in `/cart/add` excludes any product where `is_sample` is truthy (`server.js:138`).
3. Cart entries are bulk inserted using `await db\`INSERT INTO cart_items ${db(cartEntries)}\`` (`server.js:150`).
4. During checkout, file selection depends on DB `item.is_sample`; truthy gives `*_sample`, falsy gives full file (`server.js:170`).

I also checked frontend behavior in `site/main.js`:

1. UI sends `is_sample: true/false` from button text (`site/main.js:56`, `site/main.js:61`).
2. There is no server-side validation that request objects have consistent keys.

## Root Cause

The exploit comes from a mismatch between:

1. Price calculation using raw user JSON (`productsToAdd`) before insert.
2. Bun SQL helper `db(cartEntries)` inferring insert columns from object keys.

In `solve.py`, I exploited this by sending two objects in one `products` array:

1. First object: cheap book with **no** `is_sample` key.
2. Second object: flag book with `is_sample: 1`.

Because the first object lacks `is_sample`, the Bun helper builds insert columns without `is_sample`, so the second object’s `is_sample` is dropped on insert.
That leaves DB rows with `is_sample = NULL`.

Why this works:

1. Add-time price check:
   - For the flag object, `is_sample = 1`, so it is treated as sample and excluded from `additionalSum` (`server.js:138`).
   - Only the cheap item is charged, so request passes.
2. Checkout-time file selection:
   - Inserted `is_sample` is `NULL`, which is falsy.
   - Falsy branch serves the full file (`flag.txt`) instead of `flag_sample.txt` (`server.js:170`).

I confirmed the challenge intentionally includes only `books/flag_sample.txt`, which contains just `lactf{`, while the real `flag.txt` is available remotely through the vulnerable checkout path.

## Exploit Script

I used the provided `solve.py`, which does:

1. Registers a random user.
2. Sends crafted `/cart/add` JSON with mixed keys.
3. Calls `/cart/checkout`.
4. Parses returned ZIP and prints file contents.

Critical payload:

```json
{
  "products": [
    {"book_id": "a3e33c2505a19d18"},
    {"book_id": "2a16e349fb9045fa", "is_sample": 1}
  ]
}
```

## Result

The saved output in `out` shows successful exploitation:

1. Remaining balance after add: `990`.
2. ZIP contained `flag.txt` and `part-time-parliament.pdf`.
3. `flag.txt` content was printed directly.

Recovered flag:

`lactf{hojicha_chocolate_dubai_labubu}`
