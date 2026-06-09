from __future__ import annotations

import hmac
import html
import json
import mimetypes
import os
import secrets
import shutil
import socket
import smtplib
import threading
import time
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import default
from hashlib import pbkdf2_hmac, sha256
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).parent.resolve()
PUBLIC = ROOT / "public"
STORAGE = ROOT / "storage"
FILES = STORAGE / "files"
INDEX = STORAGE / "shares.json"
USERS = STORAGE / "users.json"
PENDING_AUTH = STORAGE / "pending_auth.json"
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
SESSION_SECRET = secrets.token_bytes(32)
SESSION_COOKIE = "quickshare_session"
CLEANUP_INTERVAL_SECONDS = int(os.environ.get("QUICK_SHARE_CLEANUP_INTERVAL", "60"))
VERIFY_CODE_TTL_SECONDS = int(os.environ.get("QUICK_SHARE_VERIFY_CODE_TTL", "900"))
VERIFY_RESEND_COOLDOWN_SECONDS = int(os.environ.get("QUICK_SHARE_VERIFY_RESEND_COOLDOWN", "120"))


def now() -> int:
    return int(time.time())


def ensure_storage() -> None:
    FILES.mkdir(parents=True, exist_ok=True)
    if not INDEX.exists():
        INDEX.write_text("{}", encoding="utf-8")
    if not USERS.exists():
        USERS.write_text("{}", encoding="utf-8")
    if not PENDING_AUTH.exists():
        PENDING_AUTH.write_text(json.dumps({"signups": {}, "reset_tokens": {}}), encoding="utf-8")


def load_json(path: Path) -> dict[str, dict]:
    ensure_storage()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_json(path: Path, data: dict[str, dict]) -> None:
    ensure_storage()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_shares() -> dict[str, dict]:
    return load_json(INDEX)


def save_shares(shares: dict[str, dict]) -> None:
    save_json(INDEX, shares)


def load_users() -> dict[str, dict]:
    return load_json(USERS)


def save_users(users: dict[str, dict]) -> None:
    save_json(USERS, users)


def load_pending_auth() -> dict[str, dict]:
    ensure_storage()
    data = load_json(PENDING_AUTH)
    if "signups" not in data:
        data["signups"] = {}
    if "reset_tokens" not in data:
        data["reset_tokens"] = {}
    return data


def save_pending_auth(data: dict[str, dict]) -> None:
    ensure_storage()
    if "signups" not in data:
        data["signups"] = {}
    if "reset_tokens" not in data:
        data["reset_tokens"] = {}
    PENDING_AUTH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def new_id(existing: dict[str, dict], length: int = 7) -> str:
    while True:
        value = secrets.token_urlsafe(5).replace("-", "").replace("_", "")[:length]
        if value not in existing:
            return value


def expiry_from_hours(hours: str | None, allow_never: bool = False, max_hours: int = 48) -> int | None:
    if not hours:
        return now() + 24 * 3600
    if hours == "never":
        if allow_never:
            return None
        return now() + max_hours * 3600
    try:
        value = int(hours)
    except ValueError:
        value = 24
    value = max(1, min(value, max_hours))
    return now() + value * 3600


def is_expired(share: dict) -> bool:
    expires_at = share.get("expires_at")
    return bool(expires_at and expires_at <= now())


def cleanup_expired() -> None:
    shares = load_shares()
    changed = False
    for share_id, share in list(shares.items()):
        if is_expired(share):
            if share.get("kind") == "file":
                path = FILES / f"{share_id}.bin"
                if path.exists():
                    path.unlink()
            del shares[share_id]
            changed = True
    if changed:
        save_shares(shares)
    pending = load_pending_auth()
    pending_changed = False
    for email, signup in list(pending["signups"].items()):
        expires_at = signup.get("signup_code_expires_at") or 0
        if expires_at and expires_at <= now():
            del pending["signups"][email]
            pending_changed = True
    for token, reset_data in list(pending["reset_tokens"].items()):
        expires_at = reset_data.get("expires_at") or 0
        if expires_at and expires_at <= now():
            del pending["reset_tokens"][token]
            pending_changed = True
    if pending_changed:
        save_pending_auth(pending)


def local_addresses() -> list[str]:
    addresses = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        addresses.add(sock.getsockname()[0])
        sock.close()
    except OSError:
        pass
    return sorted(ip for ip in addresses if "." in ip)


def parse_multipart(body: bytes, content_type: str) -> dict[str, object]:
    message = BytesParser(policy=default).parsebytes(
        b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + body
    )
    fields: dict[str, object] = {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename:
            fields[name] = {
                "filename": Path(filename).name,
                "content_type": part.get_content_type(),
                "data": payload,
            }
        else:
            fields[name] = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    return fields


def hash_password(password: str, salt_hex: str) -> str:
    return pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 120_000).hex()


def hash_code(email: str, code: str) -> str:
    return hmac.new(SESSION_SECRET, f"code:{email.lower()}:{code}".encode("utf-8"), sha256).hexdigest()


def share_signature(share_id: str, password_hash: str) -> str:
    return hmac.new(SESSION_SECRET, f"share:{share_id}:{password_hash}".encode("utf-8"), sha256).hexdigest()


def user_signature(user_id: str) -> str:
    return hmac.new(SESSION_SECRET, f"user:{user_id}".encode("utf-8"), sha256).hexdigest()


def normalize_username(username: str) -> str:
    return username.strip().lower()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def new_code(length: int = 6) -> str:
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))


def detect_device_label(user_agent: str) -> str:
    ua = user_agent.lower()
    if "iphone" in ua:
        return "iPhone"
    if "ipad" in ua:
        return "iPad"
    if "android" in ua and "mobile" in ua:
        return "Android phone"
    if "android" in ua:
        return "Android tablet"
    if "windows" in ua:
        return "Windows"
    if "mac os x" in ua or "macintosh" in ua:
        return "Mac"
    if "linux" in ua:
        return "Linux"
    return "Unknown device"


def detect_browser_label(user_agent: str) -> str:
    ua = user_agent.lower()
    if "edg/" in ua:
        return "Edge"
    if "chrome/" in ua and "edg/" not in ua:
        return "Chrome"
    if "firefox/" in ua:
        return "Firefox"
    if "safari/" in ua and "chrome/" not in ua:
        return "Safari"
    if "samsungbrowser/" in ua:
        return "Samsung Internet"
    return "Browser"


def build_view_stats(share: dict) -> dict:
    events = share.get("open_events") or []
    total_opens = len(events)
    qr_opens = sum(1 for event in events if event.get("source") == "qr")
    link_opens = total_opens - qr_opens
    device_map: dict[str, int] = {}
    for event in events:
        label = str(event.get("device") or "Unknown device")
        device_map[label] = device_map.get(label, 0) + 1
    top_devices = [
        {"label": label, "count": count}
        for label, count in sorted(device_map.items(), key=lambda item: (-item[1], item[0]))[:4]
    ]
    recent = []
    for event in events[-5:][::-1]:
        recent.append(
            {
                "device": event.get("device") or "Unknown device",
                "browser": event.get("browser") or "Browser",
                "source": event.get("source") or "link",
                "opened_at": event.get("opened_at") or 0,
            }
        )
    unique_devices = len({f"{event.get('device')}|{event.get('browser')}" for event in events})
    return {
        "total_opens": total_opens,
        "qr_opens": qr_opens,
        "link_opens": link_opens,
        "unique_devices": unique_devices,
        "top_devices": top_devices,
        "recent": recent,
    }


def find_user_by_identifier(users: dict[str, dict], identifier: str) -> dict | None:
    normalized = normalize_username(identifier)
    email = normalize_email(identifier)
    for user in users.values():
        if normalize_username(user.get("username", "")) == normalized:
            return user
        if normalize_email(user.get("email", "")) == email:
            return user
    return None


def seconds_until_retry(sent_at: int | None) -> int:
    if not sent_at:
        return 0
    return max(0, VERIFY_RESEND_COOLDOWN_SECONDS - (now() - sent_at))


def cleanup_user_reset_state(user: dict) -> None:
    user["reset_code_hash"] = None
    user["reset_code_expires_at"] = None
    user["reset_code_sent_at"] = None


def smtp_settings() -> dict[str, str | int | bool] | None:
    host = os.environ.get("QUICK_SHARE_SMTP_HOST", "").strip()
    from_email = os.environ.get("QUICK_SHARE_SMTP_FROM", "").strip()
    if not host or not from_email:
        return None
    return {
        "host": host,
        "port": int(os.environ.get("QUICK_SHARE_SMTP_PORT", "587")),
        "username": os.environ.get("QUICK_SHARE_SMTP_USERNAME", "").strip(),
        "password": os.environ.get("QUICK_SHARE_SMTP_PASSWORD", ""),
        "from_email": from_email,
        "use_starttls": os.environ.get("QUICK_SHARE_SMTP_STARTTLS", "true").lower() != "false",
    }


def send_email_code(email: str, subject: str, heading: str, code: str) -> None:
    settings = smtp_settings()
    if not settings:
        raise RuntimeError("Email sending is not configured on this server yet")

    from_email = str(settings["from_email"])
    message = EmailMessage()
    message["From"] = f"Quick Share <{from_email}>"
    message["To"] = email
    message["Subject"] = subject
    message.set_content(
        f"{heading}\n\n"
        f"You requested a Quick Share verification code.\n\n"
        f"Code: {code}\n\n"
        f"This code expires in {VERIFY_CODE_TTL_SECONDS // 60} minutes.\n"
        f"If you did not request this, you can ignore this email."
    )
    message.add_alternative(
        f"""
        <html>
          <body style="font-family:Segoe UI,Arial,sans-serif;background:#07111f;color:#eff7ff;padding:24px;">
            <div style="max-width:560px;margin:0 auto;background:#0d1d32;border:1px solid rgba(148,180,216,0.18);border-radius:20px;padding:28px;">
              <h2 style="margin:0 0 12px;color:#eff7ff;">{html.escape(heading)}</h2>
              <p style="margin:0 0 18px;color:#cddcf0;">You requested a Quick Share verification code.</p>
              <div style="display:inline-block;padding:14px 18px;border-radius:14px;background:linear-gradient(135deg,#49a6ff,#64f4c4);color:#06111e;font-size:28px;font-weight:800;letter-spacing:0.12em;">
                {html.escape(code)}
              </div>
              <p style="margin:18px 0 0;color:#cddcf0;">This code expires in {VERIFY_CODE_TTL_SECONDS // 60} minutes.</p>
              <p style="margin:10px 0 0;color:#9eb3c9;">If you did not request this, you can ignore this email.</p>
            </div>
          </body>
        </html>
        """,
        subtype="html",
    )

    with smtplib.SMTP(str(settings["host"]), int(settings["port"]), timeout=20) as smtp:
        smtp.ehlo()
        if settings["use_starttls"]:
            smtp.starttls()
            smtp.ehlo()
        username = str(settings["username"])
        password = str(settings["password"])
        if username:
            smtp.login(username, password)
        smtp.send_message(message)


def cleanup_loop() -> None:
    while True:
        try:
            cleanup_expired()
        except Exception as exc:
            print(f"[cleanup] {exc}")
        time.sleep(max(15, CLEANUP_INTERVAL_SECONDS))


class ShareHandler(BaseHTTPRequestHandler):
    server_version = "QuickShare/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def send_json(self, payload: object, status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_text(self, text: str, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def cookies(self) -> SimpleCookie:
        jar = SimpleCookie()
        jar.load(self.headers.get("Cookie", ""))
        return jar

    def read_form(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_UPLOAD_BYTES:
            raise ValueError("Upload is too large")
        content_type = self.headers.get("Content-Type", "")
        body = self.rfile.read(length)
        if "multipart/form-data" not in content_type:
            return {}
        return parse_multipart(body, content_type)

    def share_cookie_name(self, share_id: str) -> str:
        return f"quickshare_{share_id}"

    def current_user(self) -> dict | None:
        cookie = self.cookies().get(SESSION_COOKIE)
        if not cookie:
            return None
        raw = cookie.value
        if ":" not in raw:
            return None
        user_id, signature = raw.split(":", 1)
        expected = user_signature(user_id)
        if not hmac.compare_digest(signature, expected):
            return None
        users = load_users()
        return users.get(user_id)

    def set_user_cookie(self, user: dict, remember: bool = False) -> None:
        token = f"{user['id']}:{user_signature(user['id'])}"
        cookie = f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax"
        if remember:
            cookie += "; Max-Age=2592000"
        self.send_header("Set-Cookie", cookie)

    def clear_user_cookie(self) -> None:
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax",
        )

    def set_share_cookie(self, share: dict) -> None:
        token = share_signature(share["id"], share["password_hash"])
        self.send_header("Set-Cookie", f"{self.share_cookie_name(share['id'])}={token}; Path=/; HttpOnly; SameSite=Lax")

    def clear_share_cookie(self, share_id: str) -> None:
        self.send_header(
            "Set-Cookie",
            f"{self.share_cookie_name(share_id)}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax",
        )

    def is_owner(self, share: dict, user: dict | None = None) -> bool:
        viewer = user or self.current_user()
        return bool(viewer and share.get("owner_user_id") == viewer.get("id"))

    def is_authorized(self, share: dict) -> bool:
        if self.is_owner(share):
            return True
        password_hash = share.get("password_hash")
        if not password_hash:
            return True
        cookie = self.cookies().get(self.share_cookie_name(share["id"]))
        if not cookie:
            return False
        expected = share_signature(share["id"], password_hash)
        return hmac.compare_digest(cookie.value, expected)

    def serialize_share(self, share: dict, include_text: bool = False) -> dict:
        base = f"http://{self.headers.get('Host', 'localhost:8787')}"
        item = {key: share.get(key) for key in ("id", "kind", "filename", "size", "created_at", "expires_at")}
        item["password_protected"] = bool(share.get("password_hash"))
        item["saved_to_profile"] = bool(share.get("owner_user_id"))
        item["url"] = f"{base}/s/{share['id']}"
        item["raw_url"] = f"{base}/raw/{share['id']}"
        item["download_url"] = f"{base}/download/{share['id']}"
        if share.get("kind") == "text" and include_text:
            item["text"] = share.get("text", "")
        if share.get("owner_user_id"):
            item["view_stats"] = build_view_stats(share)
        return item

    def track_share_open(self, share: dict, source: str = "link") -> None:
        shares = load_shares()
        stored_share = shares.get(share["id"])
        if not stored_share:
            return
        user_agent = self.headers.get("User-Agent", "").strip()
        event = {
            "opened_at": now(),
            "source": "qr" if source == "qr" else "link",
            "device": detect_device_label(user_agent),
            "browser": detect_browser_label(user_agent),
        }
        events = list(stored_share.get("open_events") or [])
        events.append(event)
        stored_share["open_events"] = events[-60:]
        save_shares(shares)

    def get_share(self, share_id: str) -> dict | None:
        shares = load_shares()
        share = shares.get(share_id.strip("/"))
        if not share or is_expired(share):
            return None
        return share

    def do_GET(self) -> None:
        cleanup_expired()
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/shares":
            self.send_json(self.public_share_list())
            return
        if path == "/api/profile/shares":
            self.handle_profile_shares()
            return
        if path == "/api/meta":
            self.send_json({"addresses": local_addresses(), "port": self.server.server_port})
            return
        if path == "/api/me":
            self.handle_me()
            return
        if path.startswith("/api/share/"):
            self.handle_share_api(path.removeprefix("/api/share/"))
            return
        if path.startswith("/s/"):
            source = parse_qs(parsed.query).get("src", ["link"])[0]
            self.handle_share_page(path.removeprefix("/s/"), source=source)
            return
        if path.startswith("/raw/"):
            source = parse_qs(parsed.query).get("src", ["link"])[0]
            self.handle_raw(path.removeprefix("/raw/"), source=source)
            return
        if path.startswith("/download/"):
            source = parse_qs(parsed.query).get("src", ["link"])[0]
            self.handle_download(path.removeprefix("/download/"), source=source)
            return
        self.serve_static(path)

    def do_POST(self) -> None:
        cleanup_expired()
        if self.path.startswith("/unlock/"):
            self.handle_unlock(self.path.removeprefix("/unlock/"))
            return
        if self.path == "/api/auth/signup":
            self.handle_signup()
            return
        if self.path == "/api/auth/verify-signup":
            self.handle_verify_signup()
            return
        if self.path == "/api/auth/resend-signup-code":
            self.handle_resend_signup_code()
            return
        if self.path == "/api/auth/login":
            self.handle_login()
            return
        if self.path == "/api/auth/send-password-reset":
            self.handle_send_password_reset()
            return
        if self.path == "/api/auth/verify-reset-code":
            self.handle_verify_reset_code()
            return
        if self.path == "/api/auth/reset-password":
            self.handle_reset_password()
            return
        if self.path == "/api/auth/logout":
            self.handle_logout()
            return
        if self.path.startswith("/api/share-again/"):
            self.handle_share_again(self.path.removeprefix("/api/share-again/"))
            return
        if self.path != "/api/share":
            self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        self.handle_create_share()

    def do_DELETE(self) -> None:
        if not self.path.startswith("/api/share/"):
            self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        share_id = self.path.removeprefix("/api/share/").strip("/")
        shares = load_shares()
        share = shares.get(share_id)
        if not share:
            self.send_json({"error": "Share not found"}, HTTPStatus.NOT_FOUND)
            return
        if share.get("owner_user_id") and not self.is_owner(share):
            self.send_json({"error": "That share belongs to another account"}, HTTPStatus.FORBIDDEN)
            return
        shares.pop(share_id, None)
        if share.get("kind") == "file":
            path = FILES / f"{share_id}.bin"
            if path.exists():
                path.unlink()
        save_shares(shares)
        data = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.clear_share_cookie(share_id)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def handle_me(self) -> None:
        user = self.current_user()
        if not user:
            self.send_json({"authenticated": False})
            return
        self.send_json({"authenticated": True, "user": {"id": user["id"], "username": user["username"], "email": user.get("email", "")}})

    def public_share_list(self) -> list[dict]:
        shares = load_shares()
        items = []
        for share in sorted(shares.values(), key=lambda item: item["created_at"], reverse=True):
            if share.get("owner_user_id"):
                continue
            items.append(self.serialize_share(share, include_text=share.get("kind") == "text" and not share.get("password_hash")))
        return items

    def handle_profile_shares(self) -> None:
        user = self.current_user()
        if not user:
            self.send_json({"error": "Sign in first"}, HTTPStatus.UNAUTHORIZED)
            return
        shares = load_shares()
        items = [
            self.serialize_share(share, include_text=share.get("kind") == "text")
            for share in sorted(shares.values(), key=lambda item: item["created_at"], reverse=True)
            if share.get("owner_user_id") == user["id"]
        ]
        self.send_json(items)

    def handle_share_again(self, share_id: str) -> None:
        user = self.current_user()
        if not user:
            self.send_json({"error": "Sign in first"}, HTTPStatus.UNAUTHORIZED)
            return
        shares = load_shares()
        original = shares.get(share_id.strip("/"))
        if not original:
            self.send_json({"error": "Share not found or expired"}, HTTPStatus.NOT_FOUND)
            return
        if original.get("owner_user_id") != user.get("id"):
            self.send_json({"error": "That share belongs to another account"}, HTTPStatus.FORBIDDEN)
            return
        new_share_id = new_id(shares)
        duplicated = {
            "id": new_share_id,
            "kind": original["kind"],
            "size": original.get("size", 0),
            "created_at": now(),
            "expires_at": None,
            "password_salt": original.get("password_salt"),
            "password_hash": original.get("password_hash"),
            "owner_user_id": user["id"],
            "open_events": [],
        }
        if original["kind"] == "text":
            duplicated["text"] = original.get("text", "")
        else:
            duplicated["filename"] = original.get("filename", "download.bin")
            duplicated["content_type"] = original.get("content_type") or "application/octet-stream"
            source_path = FILES / f"{original['id']}.bin"
            target_path = FILES / f"{new_share_id}.bin"
            if not source_path.exists():
                self.send_json({"error": "Original file is missing"}, HTTPStatus.NOT_FOUND)
                return
            shutil.copyfile(source_path, target_path)
        shares[new_share_id] = duplicated
        save_shares(shares)
        include_text = duplicated["kind"] == "text" and (not duplicated.get("password_hash") or self.is_owner(duplicated, user))
        self.send_json(
            {
                "ok": True,
                "message": "New share link created from your saved item.",
                "share": self.serialize_share(duplicated, include_text=include_text),
            }
        )

    def handle_signup(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        username = str(fields.get("username") or "").strip()
        email = normalize_email(str(fields.get("email") or ""))
        password = str(fields.get("password") or "")
        normalized = normalize_username(username)
        if len(normalized) < 3:
            self.send_json({"error": "Username needs at least 3 characters"}, HTTPStatus.BAD_REQUEST)
            return
        if "@" not in email or "." not in email:
            self.send_json({"error": "Enter a valid email address"}, HTTPStatus.BAD_REQUEST)
            return
        if len(password) < 4:
            self.send_json({"error": "Password needs at least 4 characters"}, HTTPStatus.BAD_REQUEST)
            return
        users = load_users()
        pending = load_pending_auth()
        if any(normalize_username(user["username"]) == normalized for user in users.values()):
            self.send_json({"error": "That username is already taken"}, HTTPStatus.CONFLICT)
            return
        if any(normalize_email(user.get("email", "")) == email for user in users.values()):
            self.send_json({"error": "That email is already in use"}, HTTPStatus.CONFLICT)
            return
        if any(normalize_username(item.get("username", "")) == normalized for item in pending["signups"].values()):
            self.send_json({"error": "That username is already waiting for verification"}, HTTPStatus.CONFLICT)
            return
        if email in pending["signups"]:
            self.send_json({"error": "That email is already waiting for verification"}, HTTPStatus.CONFLICT)
            return
        salt = secrets.token_hex(16)
        pending["signups"][email] = {
            "username": username,
            "email": email,
            "password_salt": salt,
            "password_hash": hash_password(password, salt),
            "created_at": now(),
            "signup_code_hash": None,
            "signup_code_expires_at": None,
            "signup_code_sent_at": None,
        }
        save_pending_auth(pending)
        self.send_json(
            {
                "ok": True,
                "requires_verification": True,
                "email": email,
                "message": "Account created. Use Send code to get your verification email.",
                "cooldown_seconds": VERIFY_RESEND_COOLDOWN_SECONDS,
            }
        )

    def handle_verify_signup(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        email = normalize_email(str(fields.get("email") or ""))
        code = str(fields.get("code") or "").strip()
        pending = load_pending_auth()
        signup = pending["signups"].get(email)
        if not signup:
            self.send_json({"error": "No pending signup found for that email"}, HTTPStatus.NOT_FOUND)
            return
        if not code:
            self.send_json({"error": "Enter the verification code"}, HTTPStatus.BAD_REQUEST)
            return
        if not signup.get("signup_code_hash"):
            self.send_json({"error": "Send the verification code first"}, HTTPStatus.BAD_REQUEST)
            return
        if (signup.get("signup_code_expires_at") or 0) < now():
            self.send_json({"error": "That verification code expired. Sign up again to get a new one."}, HTTPStatus.UNAUTHORIZED)
            return
        expected = signup.get("signup_code_hash") or ""
        if not hmac.compare_digest(expected, hash_code(email, code)):
            self.send_json({"error": "Wrong verification code"}, HTTPStatus.UNAUTHORIZED)
            return
        users = load_users()
        normalized = normalize_username(signup["username"])
        if any(normalize_username(user["username"]) == normalized for user in users.values()):
            self.send_json({"error": "That username was taken while you were verifying. Sign up again."}, HTTPStatus.CONFLICT)
            return
        if any(normalize_email(user.get("email", "")) == email for user in users.values()):
            self.send_json({"error": "That email is already in use. Sign up again."}, HTTPStatus.CONFLICT)
            return
        user_id = new_id(users, length=8)
        user = {
            "id": user_id,
            "username": signup["username"],
            "email": email,
            "password_salt": signup["password_salt"],
            "password_hash": signup["password_hash"],
            "created_at": signup["created_at"],
            "verified_at": now(),
            "reset_code_hash": None,
            "reset_code_expires_at": None,
            "reset_code_sent_at": None,
        }
        users[user_id] = user
        save_users(users)
        del pending["signups"][email]
        save_pending_auth(pending)
        self.send_response(200)
        self.set_user_cookie(user)
        payload = json.dumps({"ok": True, "user": {"id": user["id"], "username": user["username"], "email": user["email"]}}).encode("utf-8")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_resend_signup_code(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        email = normalize_email(str(fields.get("email") or ""))
        pending = load_pending_auth()
        signup = pending["signups"].get(email)
        if not signup:
            self.send_json({"error": "No pending signup found for that email"}, HTTPStatus.NOT_FOUND)
            return
        retry_after = seconds_until_retry(signup.get("signup_code_sent_at"))
        if retry_after:
            self.send_json(
                {"error": f"Please wait {retry_after} seconds before sending another code.", "retry_after": retry_after},
                HTTPStatus.TOO_MANY_REQUESTS,
            )
            return
        code = new_code()
        signup["signup_code_hash"] = hash_code(email, code)
        signup["signup_code_expires_at"] = now() + VERIFY_CODE_TTL_SECONDS
        signup["signup_code_sent_at"] = now()
        save_pending_auth(pending)
        try:
            send_email_code(email, "Verify your Quick Share account", "Finish your signup", code)
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.SERVICE_UNAVAILABLE)
            return
        except OSError as exc:
            self.send_json({"error": f"Could not send verification email: {exc}"}, HTTPStatus.BAD_GATEWAY)
            return
        self.send_json({"ok": True, "message": "Verification code sent.", "cooldown_seconds": VERIFY_RESEND_COOLDOWN_SECONDS})

    def handle_login(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        identifier = str(fields.get("username") or "").strip()
        password = str(fields.get("password") or "")
        remember = str(fields.get("remember_me") or "").lower() == "true"
        users = load_users()
        user = find_user_by_identifier(users, identifier)
        if not user:
            self.send_json({"error": "Unknown username or password"}, HTTPStatus.UNAUTHORIZED)
            return
        if not user.get("verified_at"):
            self.send_json({"error": "Verify your email before signing in"}, HTTPStatus.FORBIDDEN)
            return
        expected = hash_password(password, user["password_salt"])
        if not hmac.compare_digest(expected, user["password_hash"]):
            self.send_json({"error": "Unknown username or password"}, HTTPStatus.UNAUTHORIZED)
            return
        self.send_response(200)
        self.set_user_cookie(user, remember=remember)
        payload = json.dumps({"ok": True, "user": {"id": user["id"], "username": user["username"], "email": user.get("email", "")}}).encode("utf-8")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_send_password_reset(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        email = normalize_email(str(fields.get("email") or ""))
        if "@" not in email or "." not in email:
            self.send_json({"error": "Enter a valid email address"}, HTTPStatus.BAD_REQUEST)
            return
        users = load_users()
        user = next((item for item in users.values() if normalize_email(item.get("email", "")) == email), None)
        if not user or not user.get("verified_at"):
            self.send_json({"error": "No verified account found for that email"}, HTTPStatus.NOT_FOUND)
            return
        retry_after = seconds_until_retry(user.get("reset_code_sent_at"))
        if retry_after:
            self.send_json(
                {"error": f"Please wait {retry_after} seconds before sending another code.", "retry_after": retry_after},
                HTTPStatus.TOO_MANY_REQUESTS,
            )
            return
        cleanup_user_reset_state(user)
        code = new_code()
        user["reset_code_hash"] = hash_code(email, code)
        user["reset_code_expires_at"] = now() + VERIFY_CODE_TTL_SECONDS
        user["reset_code_sent_at"] = now()
        save_users(users)
        try:
            send_email_code(email, "Quick Share password reset", "Use this code to reset your password", code)
        except RuntimeError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.SERVICE_UNAVAILABLE)
            return
        except OSError as exc:
            self.send_json({"error": f"Could not send reset email: {exc}"}, HTTPStatus.BAD_GATEWAY)
            return
        self.send_json(
            {
                "ok": True,
                "message": "Reset code sent",
                "email": email,
                "cooldown_seconds": VERIFY_RESEND_COOLDOWN_SECONDS,
            }
        )

    def handle_verify_reset_code(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        email = normalize_email(str(fields.get("email") or ""))
        code = str(fields.get("code") or "").strip()
        users = load_users()
        user = next((item for item in users.values() if normalize_email(item.get("email", "")) == email), None)
        if not user or not user.get("verified_at"):
            self.send_json({"error": "No verified account found for that email"}, HTTPStatus.NOT_FOUND)
            return
        if not code:
            self.send_json({"error": "Enter the reset code"}, HTTPStatus.BAD_REQUEST)
            return
        if (user.get("reset_code_expires_at") or 0) < now():
            self.send_json({"error": "That reset code expired. Request a new one."}, HTTPStatus.UNAUTHORIZED)
            return
        expected = user.get("reset_code_hash") or ""
        if not hmac.compare_digest(expected, hash_code(email, code)):
            self.send_json({"error": "Wrong reset code"}, HTTPStatus.UNAUTHORIZED)
            return
        pending = load_pending_auth()
        token = secrets.token_urlsafe(24)
        pending["reset_tokens"][token] = {"email": email, "expires_at": now() + VERIFY_CODE_TTL_SECONDS}
        save_pending_auth(pending)
        cleanup_user_reset_state(user)
        save_users(users)
        self.send_json({"ok": True, "message": "Reset code verified", "token": token})

    def handle_reset_password(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        token = str(fields.get("token") or "").strip()
        password = str(fields.get("password") or "")
        if not token:
            self.send_json({"error": "Missing reset session"}, HTTPStatus.BAD_REQUEST)
            return
        if len(password) < 4:
            self.send_json({"error": "Password needs at least 4 characters"}, HTTPStatus.BAD_REQUEST)
            return
        pending = load_pending_auth()
        reset_data = pending["reset_tokens"].get(token)
        if not reset_data or (reset_data.get("expires_at") or 0) < now():
            self.send_json({"error": "That reset session expired. Start again."}, HTTPStatus.UNAUTHORIZED)
            return
        email = normalize_email(reset_data.get("email", ""))
        users = load_users()
        user = next((item for item in users.values() if normalize_email(item.get("email", "")) == email), None)
        if not user or not user.get("verified_at"):
            self.send_json({"error": "No verified account found for that email"}, HTTPStatus.NOT_FOUND)
            return
        salt = secrets.token_hex(16)
        user["password_salt"] = salt
        user["password_hash"] = hash_password(password, salt)
        cleanup_user_reset_state(user)
        save_users(users)
        del pending["reset_tokens"][token]
        save_pending_auth(pending)
        self.send_json({"ok": True, "message": "Password reset complete"})

    def handle_logout(self) -> None:
        self.send_response(200)
        self.clear_user_cookie()
        payload = json.dumps({"ok": True}).encode("utf-8")
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def handle_create_share(self) -> None:
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return

        kind = str(fields.get("kind") or "text")
        password = str(fields.get("password") or "")
        save_to_profile = str(fields.get("save_to_profile") or "").lower() == "true"
        user = self.current_user()
        expires_at = expiry_from_hours(
            str(fields.get("expires") or "24"),
            allow_never=bool(user),
            max_hours=24 * 365 if user else 48,
        )
        shares = load_shares()
        share_id = new_id(shares)
        password_salt = secrets.token_hex(16) if password else None
        password_hash = hash_password(password, password_salt) if password_salt else None
        owner_user_id = user["id"] if user and save_to_profile else None

        if kind == "file":
            file_info = fields.get("file")
            if not isinstance(file_info, dict) or not file_info.get("data"):
                self.send_json({"error": "Choose a file first"}, HTTPStatus.BAD_REQUEST)
                return
            data = file_info["data"]
            filename = str(file_info.get("filename") or "download.bin")
            (FILES / f"{share_id}.bin").write_bytes(data)
            shares[share_id] = {
                "id": share_id,
                "kind": "file",
                "filename": filename,
                "content_type": file_info.get("content_type") or "application/octet-stream",
                "size": len(data),
                "created_at": now(),
                "expires_at": expires_at,
                "password_salt": password_salt,
                "password_hash": password_hash,
                "owner_user_id": owner_user_id,
                "open_events": [],
            }
        else:
            text_value = str(fields.get("text") or "").strip()
            if not text_value:
                self.send_json({"error": "Paste some text first"}, HTTPStatus.BAD_REQUEST)
                return
            shares[share_id] = {
                "id": share_id,
                "kind": "text",
                "text": text_value,
                "size": len(text_value.encode("utf-8")),
                "created_at": now(),
                "expires_at": expires_at,
                "password_salt": password_salt,
                "password_hash": password_hash,
                "owner_user_id": owner_user_id,
                "open_events": [],
            }

        save_shares(shares)
        include_text = shares[share_id]["kind"] == "text" and (not password_hash or self.is_owner(shares[share_id], user))
        self.send_json(self.serialize_share(shares[share_id], include_text=include_text))

    def handle_share_api(self, share_id: str) -> None:
        share = self.get_share(share_id)
        if not share:
            self.send_json({"error": "Share not found or expired"}, HTTPStatus.NOT_FOUND)
            return
        if not self.is_authorized(share):
            self.send_json({"error": "Password required"}, HTTPStatus.UNAUTHORIZED)
            return
        include_text = share.get("kind") == "text"
        self.send_json(self.serialize_share(share, include_text=include_text))

    def handle_raw(self, share_id: str, source: str = "link") -> None:
        share = self.get_share(share_id)
        if not share:
            self.send_text("Share not found or expired", HTTPStatus.NOT_FOUND)
            return
        if not self.is_authorized(share):
            self.redirect(f"/s/{share['id']}")
            return
        self.track_share_open(share, source)
        if share["kind"] == "text":
            self.send_text(share.get("text", ""))
            return
        self.handle_download(share_id, inline=True, source=source)

    def handle_download(self, share_id: str, inline: bool = False, source: str = "link") -> None:
        share = self.get_share(share_id)
        if not share or share["kind"] != "file":
            self.send_text("File not found or expired", HTTPStatus.NOT_FOUND)
            return
        if not self.is_authorized(share):
            self.redirect(f"/s/{share['id']}")
            return
        self.track_share_open(share, source)
        path = FILES / f"{share['id']}.bin"
        if not path.exists():
            self.send_text("File missing", HTTPStatus.NOT_FOUND)
            return
        self.send_response(200)
        self.send_header("Content-Type", share.get("content_type") or "application/octet-stream")
        disposition = "inline" if inline else "attachment"
        self.send_header("Content-Disposition", f'{disposition}; filename="{share.get("filename", "download.bin")}"')
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        with path.open("rb") as fh:
            shutil.copyfileobj(fh, self.wfile)

    def handle_share_page(self, share_id: str, source: str = "link") -> None:
        share = self.get_share(share_id)
        if not share:
            self.send_text(render_missing_page(), HTTPStatus.NOT_FOUND, "text/html; charset=utf-8")
            return
        if not self.is_authorized(share):
            next_url = f"/s/{share['id']}?src={'qr' if source == 'qr' else 'link'}"
            self.send_text(render_unlock_page(self.serialize_share(share), next_url=next_url), content_type="text/html; charset=utf-8")
            return
        self.track_share_open(share, source)
        include_text = share.get("kind") == "text"
        self.send_text(render_share_page(self.serialize_share(share, include_text=include_text)), content_type="text/html; charset=utf-8")

    def handle_unlock(self, share_id: str) -> None:
        share = self.get_share(share_id.strip("/"))
        if not share:
            self.send_text(render_missing_page(), HTTPStatus.NOT_FOUND, "text/html; charset=utf-8")
            return
        try:
            fields = self.read_form()
        except ValueError as exc:
            self.send_text(render_unlock_page(self.serialize_share(share), error=str(exc)), HTTPStatus.BAD_REQUEST, "text/html; charset=utf-8")
            return
        password = str(fields.get("password") or "")
        next_url = str(fields.get("next") or f"/s/{share['id']}")
        if not share.get("password_hash"):
            self.redirect(next_url)
            return
        expected = hash_password(password, share["password_salt"])
        if not hmac.compare_digest(expected, share["password_hash"]):
            self.send_text(
                render_unlock_page(self.serialize_share(share), error="Wrong password. Try again."),
                HTTPStatus.UNAUTHORIZED,
                "text/html; charset=utf-8",
            )
            return
        self.send_response(302)
        self.set_share_cookie(share)
        self.send_header("Location", next_url)
        self.end_headers()

    def serve_static(self, path: str) -> None:
        requested = "index.html" if path in ("", "/") else unquote(path.lstrip("/"))
        file_path = (PUBLIC / requested).resolve()
        if not str(file_path).startswith(str(PUBLIC)) or not file_path.exists() or not file_path.is_file():
            self.send_text("Not found", HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def render_missing_page() -> str:
    return """<!doctype html><html><head><meta charset="utf-8"><title>Share missing</title><link rel="stylesheet" href="/styles.css"></head><body><main class="single"><h1>Share expired or missing</h1><p>This temporary link is no longer available.</p><a class="button" href="/">Create a new share</a></main></body></html>"""


def render_unlock_page(share: dict, error: str = "", next_url: str | None = None) -> str:
    escaped_id = html.escape(share["id"])
    escaped_error = html.escape(error)
    escaped_next = html.escape(next_url or f"/s/{share['id']}")
    label = "text share" if share["kind"] == "text" else "file share"
    filename = html.escape(share.get("filename") or "")
    details = f"<p>{filename}</p>" if filename else ""
    error_block = f'<p class="status error">{escaped_error}</p>' if error else '<p class="status"></p>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Unlock share {escaped_id}</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="single">
    <a class="back" href="/">Back to Quick Share</a>
    <div class="share-card unlock-card">
      <div class="share-meta">Protected {label} · {escaped_id}</div>
      <h2>Enter password to open this share</h2>
      {details}
      <form method="post" action="/unlock/{escaped_id}" class="unlock-form" enctype="multipart/form-data">
        <input type="hidden" name="next" value="{escaped_next}">
        <label class="field">
          <span>Password</span>
          <input type="password" name="password" placeholder="Enter share password" required autofocus>
        </label>
        <button class="button" type="submit">Unlock share</button>
      </form>
      {error_block}
    </div>
  </main>
</body>
</html>"""


def render_share_page(share: dict) -> str:
    escaped_id = html.escape(share["id"])
    copy_helpers = """
        <script>
          function toast(text) {
            const el = document.querySelector('.toast');
            el.textContent = text;
            el.classList.add('show');
            setTimeout(() => el.classList.remove('show'), 1600);
          }

          async function copyValue(value, label) {
            try {
              if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(value);
                toast(label + ' copied');
                return true;
              }
            } catch (error) {
              console.warn('Clipboard write failed, falling back.', error);
            }

            const input = document.createElement('textarea');
            input.value = value;
            input.setAttribute('readonly', '');
            input.style.position = 'fixed';
            input.style.opacity = '0';
            document.body.appendChild(input);
            input.focus();
            input.select();

            try {
              const copied = document.execCommand('copy');
              toast(copied ? (label + ' copied') : ('Copy ' + label.toLowerCase() + ' manually'));
              return copied;
            } catch (error) {
              console.warn('Clipboard fallback failed.', error);
              toast('Copy ' + label.toLowerCase() + ' manually');
              return false;
            } finally {
              document.body.removeChild(input);
            }
          }
        </script>
    """
    if share["kind"] == "text":
        escaped_text = html.escape(share.get("text", ""))
        body = f"""
        <div class="share-card">
          <div class="share-meta">Text share - {escaped_id}</div>
          <pre id="shareText">{escaped_text}</pre>
          <div class="actions">
            <button class="button" type="button" onclick="copyText()">Copy text</button>
            <button class="ghost" type="button" onclick="copyLink()">Copy link</button>
            <a class="ghost" href="/raw/{escaped_id}">Open raw</a>
          </div>
        </div>
        <script>
          async function copyText() {{ await copyValue(document.getElementById('shareText').innerText, 'Text'); }}
          async function copyLink() {{ await copyValue(location.href, 'Link'); }}
        </script>
        """
    else:
        filename = html.escape(share.get("filename") or "download")
        body = f"""
        <div class="share-card">
          <div class="share-meta">File share - {escaped_id}</div>
          <h2>{filename}</h2>
          <p>Open this link on another device and download the file.</p>
          <div class="actions">
            <a class="button" href="/download/{escaped_id}">Download file</a>
            <button class="ghost" type="button" onclick="copyLink()">Copy link</button>
          </div>
        </div>
        <script>
          async function copyLink() {{ await copyValue(location.href, 'Link'); }}
        </script>
        """
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Quick Share {escaped_id}</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <main class="single">
    <a class="back" href="/">Back to Quick Share</a>
    {body}
  </main>
  <div class="toast"></div>
  {copy_helpers}
</body>
</html>"""


def main() -> None:
    ensure_storage()
    threading.Thread(target=cleanup_loop, daemon=True, name="quickshare-cleanup").start()
    host = os.environ.get("QUICK_SHARE_HOST", "0.0.0.0")
    port = int(os.environ.get("QUICK_SHARE_PORT", "8787"))
    server = ThreadingHTTPServer((host, port), ShareHandler)
    print(f"Quick Share is running at http://localhost:{port}")
    print("Use your computer's LAN IP instead of localhost to grab links from another device.")
    server.serve_forever()


if __name__ == "__main__":
    main()
