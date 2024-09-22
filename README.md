# Email and password example with 2FA

Built with Astro and SQLite.

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

Create a .env file. Generate a 128 bit (16 byte) string and set the base64 encoding as `ENCRYPTION_KEY`. 

```bash
ENCRYPTION_KEY="L9pmqRJnO1ZJSQ2svbHuBA=="
```

Run the application:

```
pnpm dev
```

## User enumeration

I do not consider user enumeration to be a real vulnerability so please don't open issues on it. If you really need to prevent it, just don't use emails.
