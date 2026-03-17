---
tags:
  - web
  - uvt
---

# Cosmic Components Co. Writeup

Flag:

```text
UVT{sp4c3_sh0pp3r_3xtr40rd1n41r3_2026}
```

## Summary

This challenge looks like an SSTI problem, and `/account` does indeed render a stored bio field through a filtered Jinja-like context. That helped with reconnaissance, but the actual solve path is pure business-logic abuse:

- `/cart/add` accepts negative quantities
- `/cart/coupon` is raceable and allows duplicate coupon stacking
- the coupon discount is global to the account state, not just a single cart instance
- `/redeem-voucher` is raceable, so one voucher code can be redeemed multiple times
- each tier promotion grants `+100 BBD`

By chaining those bugs, we can buy every required product and reach `Elite`, which unlocks `/flag`.

## Useful Findings

Visible from the site:

- login works with `admin / 12345678`
- `/account` bio rendering is SSTI-like
- `/shop` exposes coupon codes:
  - `NEWCUSTOMER10`
  - `SPACESALE15`
- tier unlocks:
  - Silver: product 2
  - Gold: products 3 and 6
  - Platinum: product 4
  - Diamond: product 5

Observed during exploitation:

- first purchase to Silver gives `+100 BBD`
- next tier promotions also give `+100 BBD`
- Ion vouchers are real codes on the account page
- racing redemption of a single voucher code yields multiple successful `+25 VC` credits

## Bug 1: Negative Quantities

`/cart/add` accepts values like:

```text
quantity=-1
quantity=-2
```

That lets us create trade-in carts such as:

- `SSD x1 + RAM x-1`
- `SSD x-2 + RAM x1`

The second pattern is especially useful because it keeps the RAM coupon UI visible while producing a very small or negative subtotal.

## Bug 2: Coupon Race + Duplicate Stacking

The cart coupon endpoint does not enforce uniqueness safely under concurrency.

If you fire many simultaneous requests with:

- `NEWCUSTOMER10`
- `SPACESALE15`

the same coupon can be applied multiple times. The total compounds down quickly.

Example effect:

```text
300.00 -> 270.00 -> 229.50 -> 206.55 -> 175.57 -> ...
```

More importantly, the coupon state persists globally for the account, so you can:

1. build a RAM-containing trampoline cart
2. race coupons there
3. clear the cart
4. buy a different single-product order at the same discount factor

## Bug 3: Voucher Redemption Race

Buying `Ion Starter Voucher` items creates real pending codes such as:

```text
ION-3FD331FC
```

Redeeming the same code concurrently produces multiple successful redemptions before the backend marks it as used.

One code often yields several `+25 VC` credits instead of one.

## Exploit Chain

### 1. Reach Silver

Buy:

- `Quantum RAM Stick x1`

Race coupons until the total drops below the initial `100 BBD`, then checkout.

Result:

- tier becomes `Silver`
- wallet receives `+100 BBD`

### 2. Reach Gold

Buy:

- `Neutrino SSD Drive x1`
- `Quantum RAM Stick x-1`

Because RAM is still in the cart, the coupon UI stays available. Race coupons again until affordable, then checkout.

Result:

- tier becomes `Gold`
- another `+100 BBD`

### 3. Farm Voucher Credits

From Gold onward:

- build trampoline cart: `SSD x-2 + RAM x1`
- race coupons until a `99 x Ion Starter Voucher` order becomes affordable
- clear cart
- buy `Ion Starter Voucher x99`
- race `/redeem-voucher` on each pending code until `VC >= 9000`

### 4. Reach Platinum

Buy:

- `Ion Processor Core x1`

Pay with:

- `payment_method=vc`

Result:

- tier becomes `Platinum`

### 5. Reach Diamond

Rebuild the global discount on the trampoline cart, then buy:

- `Nvidia 8090 Ti GPU x1`

Result:

- tier becomes `Diamond`

### 6. Reach Elite

Rebuild the global discount again, then buy:

- `Dark Matter PSU x1`

Result:

- tier becomes `Elite`

### 7. Get the Flag

Open `/flag`.

## Automation

I used a short script that:

- registers a fresh random account
- climbs the tiers automatically
- farms voucher credits with redemption races
- buys the remaining products
- prints the final flag

## Notes

- The SSTI is real but not necessary for the clean solve.
- The decisive bugs are all race/business-logic issues.
- The coupon stacking is global and is what makes the later single-product purchases practical.
