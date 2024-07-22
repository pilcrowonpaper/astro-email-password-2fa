# Email and password example with 2FA

Built with Astro, SQLite, and Lucia v4 [RFC](https://github.com/lucia-auth/lucia/issues/1639).

- Password check with HaveIBeenPwned
- Email verification
- 2FA with TOTP
- 2FA recovery codes
- Password reset
- Login throttling and rate limiting

Emails are not actually sent and just logged to the console. Rate limiting is implemented using JS `Map`s.

## Initialize project

Create `sqlite.db` and run `setup.sql`.

```
sqlite3 sqlite.db
```

Run the application:

```
pnpm dev
```

## User enumeration

I do not consider user enumeration to be a real vulnerability so please don't open issues on it. If you really need to prevent it, just don't use emails.
