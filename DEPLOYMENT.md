# Quick Share Deployment

This project was built locally first, then deployed to a VPS on a separate port so it would not affect an existing site already running on port `80`.

## Local Build Flow

1. Built the Quick Share app locally on Windows.
2. Added the main sharing flow for text and files.
3. Added optional password protection for shares.
4. Added optional signup and login.
5. Added saved history for signed-in users.
6. Added expiry rules:
   - anonymous users: maximum `48 hours`
   - signed-in users: can use `never`
7. Added QR code generation for quick access.
8. Split the UI into separate pages:
   - home
   - auth
   - history
9. Polished the responsive layout for desktop and mobile.

## Local Run

Run locally with:

```powershell
python .\server.py
```

Default local URL:

```text
http://localhost:8787/
```

The server supports a custom port through:

```text
QUICK_SHARE_PORT
```

## VPS Deployment Plan

The VPS already had another project running on port `80`, so Quick Share was deployed on a different port:

```text
8788
```

## VPS Project Path

Example VPS project path:

```text
/home/<user>/Projects/quick-share
```

Equivalent shell shortcut:

```text
~/Projects/quick-share
```

## First VPS Start

The app was first started manually to verify it worked:

```bash
cd ~/Projects/quick-share
mkdir -p storage/files
nohup env QUICK_SHARE_HOST=0.0.0.0 QUICK_SHARE_PORT=8788 python3 server.py > quick-share.log 2> quick-share.err.log &
```

## Internal VPS Verification

Verified the app was listening:

```bash
ss -ltnp | grep 8788
```

Verified the app from the VPS itself:

```bash
curl http://127.0.0.1:8788/api/meta
curl http://<private-vps-ip>:8788/api/meta
```

These checks confirmed the app itself was healthy.

## Public Access Problem

At first, the app was not reachable publicly from another machine on:

```text
http://<server-ip>:8788/
```

## Cloud Ingress Rule

An ingress rule was added or confirmed in the cloud provider for:

- source: `0.0.0.0/0`
- protocol: `TCP`
- destination port: `8788`

## VPS Firewall Issue

The cloud ingress rule was not the only blocker.

The VPS firewall allowed only a small set of ports, but not `8788`, and traffic was being rejected after the allowed rules.

## VPS Firewall Fix

The port was opened on the VPS firewall so `8788` could be reached publicly.

After that, this succeeded from another machine:

```powershell
curl http://<server-ip>:8788/api/meta
```

## systemd Service

A `systemd` service was created for Quick Share:

```text
quick-share.service
```

Service file:

```ini
[Unit]
Description=Quick Share
After=network.target

[Service]
User=<user>
WorkingDirectory=/home/<user>/Projects/quick-share
Environment=QUICK_SHARE_HOST=0.0.0.0
Environment=QUICK_SHARE_PORT=8788
ExecStart=/usr/bin/python3 /home/<user>/Projects/quick-share/server.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

## Service Conflict Fix

At first, the service failed because the manual background process was already using port `8788`.

The fix was:

```bash
pkill -f "python3 .*server.py"
sudo systemctl restart quick-share
sudo systemctl status quick-share --no-pager
```

After that, the service became active and running normally.

## Final Live State

Quick Share is now live on:

```text
http://<server-ip>:8788/
```

It is now:

- running on the VPS
- managed by `systemd`
- enabled at boot
- separate from the existing site on port `80`

## Useful Service Commands

Check service status:

```bash
sudo systemctl status quick-share --no-pager
```

Restart service:

```bash
sudo systemctl restart quick-share
```

View recent logs:

```bash
sudo journalctl -u quick-share -n 50 --no-pager
```
