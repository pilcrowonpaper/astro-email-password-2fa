# Astro + Lucia v4: Email and password example with 2FA

Example project built with Astro and Lucia v4 [RFC](https://github.com/lucia-auth/lucia/issues/1639).

- Password check with HaveIBeenPwned
- Email verification
- 2FA with TOTP
- 2FA recovery codes
- Password reset
- Login throttling and rate limiting

Emails are not actually sent and just logged to the console. Rate limiting is implemented using `Map`s.

## Initialize project

Create `sqlite.db` and run `setup.sql`.

```
sqlite3 sqlite.db
```

## User enumeration

This example is "vulnerable" to user enumeration. I do not consider user enumeration to be a real vulnerability so please don't open issues on it. If you really need to prevent user enumeration, don't use emails for authentication and password reset.
