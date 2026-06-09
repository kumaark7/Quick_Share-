# Quick Share HTTPS Setup

This app is already running on the VPS at:

```text
http://127.0.0.1:8788
```

The goal here is to put Nginx in front of it and serve it at:

```text
https://quickshare.projectdarkhope.xyz
```

## 1. DNS

Create an `A` record:

- Host / Name: `quickshare`
- Value / Points to: your VPS public IP
- TTL: `Auto` or `300`

Wait until this resolves:

```powershell
nslookup quickshare.projectdarkhope.xyz
```

or:

```bash
dig +short quickshare.projectdarkhope.xyz
```

It should return your VPS public IP before you continue.

## 2. Nginx Site Config

On the VPS:

```bash
sudo nano /etc/nginx/sites-available/quickshare.projectdarkhope.xyz
```

Paste this:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name quickshare.projectdarkhope.xyz;

    client_max_body_size 200M;

    location / {
        proxy_pass http://127.0.0.1:8788;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300;
        proxy_send_timeout 300;
    }
}
```

Enable it:

```bash
sudo ln -s /etc/nginx/sites-available/quickshare.projectdarkhope.xyz /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

If another Nginx file already uses `quickshare.projectdarkhope.xyz`, remove or edit that old block first.

## 3. HTTP Check

Before HTTPS, confirm the subdomain reaches the app over plain HTTP:

```text
http://quickshare.projectdarkhope.xyz
```

If that does not load, check:

```bash
sudo nginx -t
sudo systemctl status nginx --no-pager
curl -H "Host: quickshare.projectdarkhope.xyz" http://127.0.0.1
```

## 4. HTTPS with Certbot

Install Certbot and the Nginx plugin if needed:

```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
```

Request and install the certificate:

```bash
sudo certbot --nginx -d quickshare.projectdarkhope.xyz
```

Choose the redirect-to-HTTPS option when prompted.

## 5. Final HTTPS Check

Open:

```text
https://quickshare.projectdarkhope.xyz
```

Then verify:

```bash
sudo nginx -t
sudo systemctl status nginx --no-pager
sudo systemctl status quick-share --no-pager
```

## 6. Notes

- This keeps the Python app on `127.0.0.1:8788`.
- Nginx becomes the public entry point.
- HTTPS usually improves clipboard behavior in browsers, especially on mobile.
- The app's current upload limit is `200 MB`, so the Nginx config matches that with `client_max_body_size 200M`.
