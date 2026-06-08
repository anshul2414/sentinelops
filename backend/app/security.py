"""Security primitives: password hashing, signed sessions, CSRF, rate limiting, RBAC.
No third-party crypto deps — uses Python stdlib (hashlib/hmac/secrets) with
OWASP-aligned parameters, so it is auditable and dependency-light."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime
from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session

from .database import get_db
from . import models

# SECRET_KEY must be provided in production. A random key is generated for dev so the
# app never ships with a hard-coded secret; sessions simply reset on restart.
SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
SESSION_TTL = int(os.getenv("SESSION_TTL", "43200"))        # seconds (12h)
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "auto")          # auto/true/false
SESSION_COOKIE = "sops_session"
CSRF_COOKIE = "sops_csrf"

PBKDF2_ITERS = 600_000
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- password hashing (PBKDF2-HMAC-SHA256) ----------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return f"pbkdf2_sha256${PBKDF2_ITERS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, b64salt, b64hash = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(b64salt), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(b64hash))
    except Exception:
        return False


def validate_credentials(username, email, password):
    if not USERNAME_RE.match(username or ""):
        raise ValueError("Username must be 3–32 chars (letters, numbers, underscore).")
    if not EMAIL_RE.match(email or ""):
        raise ValueError("Please enter a valid email address.")
    if not password or len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        raise ValueError("Password must contain letters and numbers.")


# ---------- signed session token (HMAC-SHA256) ----------
def _sign(payload: bytes) -> str:
    sig = hmac.new(SECRET_KEY.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload).decode() + "." + base64.urlsafe_b64encode(sig).decode()


def make_session(user) -> str:
    data = json.dumps({"uid": user.id, "u": user.username, "r": user.role,
                        "exp": int(time.time()) + SESSION_TTL}).encode()
    return _sign(data)


def read_session(token: str):
    try:
        b64data, b64sig = token.split(".")
        data = base64.urlsafe_b64decode(b64data)
        expected = hmac.new(SECRET_KEY.encode(), data, hashlib.sha256).digest()
        if not hmac.compare_digest(base64.urlsafe_b64decode(b64sig), expected):
            return None
        obj = json.loads(data)
        if obj.get("exp", 0) < time.time():
            return None
        return obj
    except Exception:
        return None


def new_api_token() -> str:
    return secrets.token_hex(32)


def cookie_secure_flag() -> bool:
    if COOKIE_SECURE == "true":
        return True
    if COOKIE_SECURE == "false":
        return False
    return os.getenv("ENV", "dev").lower() in ("prod", "production")


def set_session_cookie(resp, user):
    resp.set_cookie(SESSION_COOKIE, make_session(user), max_age=SESSION_TTL,
                    httponly=True, secure=cookie_secure_flag(), samesite="lax", path="/")


def clear_session_cookie(resp):
    resp.delete_cookie(SESSION_COOKIE, path="/")


# ---------- CSRF (double-submit cookie) ----------
def ensure_csrf(request: Request, response):
    token = request.cookies.get(CSRF_COOKIE)
    if not token:
        token = secrets.token_urlsafe(32)
        response.set_cookie(CSRF_COOKIE, token, max_age=SESSION_TTL,
                            httponly=False, secure=cookie_secure_flag(), samesite="lax", path="/")
    return token


def check_csrf(request: Request):
    cookie = request.cookies.get(CSRF_COOKIE)
    sent = request.headers.get("X-CSRF-Token")
    if not sent:
        # form submissions
        sent = getattr(request.state, "form_csrf", None)
    if not cookie or not sent or not hmac.compare_digest(cookie, sent):
        raise HTTPException(403, "CSRF validation failed")


# ---------- rate limiting (in-memory, per key) ----------
class RateLimiter:
    def __init__(self, max_attempts=8, window=300, lockout=600):
        self.max = max_attempts
        self.window = window
        self.lockout = lockout
        self.store = {}

    def hit(self, key):
        now = time.time()
        attempts, locked_until = self.store.get(key, ([], 0))
        if locked_until > now:
            return False, int(locked_until - now)
        attempts = [t for t in attempts if now - t < self.window]
        attempts.append(now)
        if len(attempts) > self.max:
            self.store[key] = (attempts, now + self.lockout)
            return False, self.lockout
        self.store[key] = (attempts, 0)
        return True, 0

    def reset(self, key):
        self.store.pop(key, None)


login_limiter = RateLimiter()


# ---------- principal resolution + RBAC dependencies ----------
def _principal(request: Request, db: Session):
    """Returns (user, method) where method is 'cookie' | 'token' | None."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        tok = auth[7:].strip()
        u = db.query(models.User).filter(models.User.api_token == tok, models.User.active == True).first()
        if u:
            return u, "token"
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        sess = read_session(cookie)
        if sess:
            u = db.query(models.User).get(sess["uid"])
            if u and u.active:
                return u, "cookie"
    return None, None


def get_current_user(request: Request, db: Session = Depends(get_db)):
    user, method = _principal(request, db)
    if not user:
        raise HTTPException(401, "Authentication required")
    request.state.user = user
    # CSRF only required for cookie-auth state-changing requests (token auth is CSRF-safe)
    if method == "cookie" and request.method not in ("GET", "HEAD", "OPTIONS"):
        check_csrf(request)
    return user


def require_role(min_role: str):
    def dep(user: models.User = Depends(get_current_user)):
        if ROLE_RANK.get(user.role, -1) < ROLE_RANK[min_role]:
            raise HTTPException(403, f"Requires '{min_role}' role or higher")
        return user
    return dep


def audit(db: Session, actor: str, action: str, detail: str = "", ip: str = ""):
    db.add(models.AuditLog(actor=actor, action=action, detail=detail[:255], ip=ip))
    db.commit()
