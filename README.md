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
- Optionally sign up or log in to save shares into your own profile history.
- Reopen, copy, and delete saved text or files from your profile history.
- Generate a QR code for quick access from another device.
- Anonymous shares can expire after 1 hour, 6 hours, 24 hours, or 48 hours.
- Signed-in users can also choose `never`.
- Store temporary data in `storage/`.

Delete the `storage/` folder whenever you want to clear everything.
