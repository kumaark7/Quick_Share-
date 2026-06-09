# Quick Share

A tiny temporary text and file host for quick sharing across devices.

## Run

```powershell
python .\server.py
```

Open:

```text
http://localhost:8787
```

To grab links from another phone or computer on the same Wi-Fi, open the server using this computer's local IP address:

```text
http://YOUR-LAN-IP:8787
```

## What it does

- Paste text and create a share page with a copy button.
- Upload a file and create a download page.
- Copy share links automatically after creation.
- Optionally protect shares with a password.
- Optionally sign up with email verification or sign in with a one-time email code.
- Sign in with username and password after the account is verified.
- Reopen, copy, and delete saved text or files from your profile history.
- Generate a QR code for quick access from another device.
- Anonymous shares can expire after 1 hour, 6 hours, 24 hours, or 48 hours.
- Signed-in users can also choose `never`.
- Expired shares are cleaned up automatically in the background even if nobody is visiting the site.
- Store temporary data in `storage/`.

Delete the `storage/` folder whenever you want to clear everything.

## Email Setup

To use email verification and email-code sign in, set these environment variables on the server:

```text
QUICK_SHARE_SMTP_HOST
QUICK_SHARE_SMTP_PORT
QUICK_SHARE_SMTP_USERNAME
QUICK_SHARE_SMTP_PASSWORD
QUICK_SHARE_SMTP_FROM
QUICK_SHARE_SMTP_STARTTLS
```

Example:

```text
QUICK_SHARE_SMTP_HOST=smtp.gmail.com
QUICK_SHARE_SMTP_PORT=587
QUICK_SHARE_SMTP_USERNAME=you@example.com
QUICK_SHARE_SMTP_PASSWORD=app-password-here
QUICK_SHARE_SMTP_FROM=you@example.com
QUICK_SHARE_SMTP_STARTTLS=true
```
