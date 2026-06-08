"""Server-side rendered authentication (login / register / logout)."""
import os
import secrets
from datetime import datetime
from fastapi import APIRouter, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .database import get_db
from . import models, security as sec

router = APIRouter()
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=TEMPLATES_DIR)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")


def _render(request: Request, name: str, status=200, **ctx):
    token = request.cookies.get(sec.CSRF_COOKIE) or secrets.token_urlsafe(32)
    resp = templates.TemplateResponse(request, name, {"csrf_token": token, **ctx}, status_code=status)
    resp.set_cookie(sec.CSRF_COOKIE, token, max_age=sec.SESSION_TTL,
                    httponly=False, secure=sec.cookie_secure_flag(), samesite="lax", path="/")
    return resp


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)):
    if sec._principal(request, db)[0]:
        return RedirectResponse("/", status_code=302)
    return _render(request, "login.html")


@router.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...),
                 csrf_token: str = Form(""), db: Session = Depends(get_db)):
    request.state.form_csrf = csrf_token
    try:
        sec.check_csrf(request)
    except Exception:
        return _render(request, "login.html", status=403, error="Session expired. Please try again.", username=username)

    ip = _client_ip(request)
    ok, wait = sec.login_limiter.hit(f"{ip}:{username}")
    if not ok:
        return _render(request, "login.html", status=429,
                       error=f"Too many attempts. Try again in {wait}s.", username=username)

    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not user.active or not sec.verify_password(password, user.password_hash):
        sec.audit(db, username, "login_failed", "invalid credentials", ip)
        return _render(request, "login.html", status=401,
                       error="Invalid username or password.", username=username)

    sec.login_limiter.reset(f"{ip}:{username}")
    user.last_login = datetime.utcnow()
    db.commit()
    sec.audit(db, user.username, "login_success", f"role={user.role}", ip)
    resp = RedirectResponse("/", status_code=302)
    sec.set_session_cookie(resp, user)
    return resp


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db)):
    if sec._principal(request, db)[0]:
        return RedirectResponse("/", status_code=302)
    first = db.query(models.User).count() == 0
    return _render(request, "register.html", first_user=first)


@router.post("/register", response_class=HTMLResponse)
def register_submit(request: Request, username: str = Form(...), email: str = Form(...),
                    password: str = Form(...), csrf_token: str = Form(""), db: Session = Depends(get_db)):
    request.state.form_csrf = csrf_token
    first = db.query(models.User).count() == 0
    try:
        sec.check_csrf(request)
    except Exception:
        return _render(request, "register.html", status=403, error="Session expired. Please try again.",
                       username=username, email=email, first_user=first)
    try:
        sec.validate_credentials(username, email, password)
    except ValueError as e:
        return _render(request, "register.html", status=400, error=str(e),
                       username=username, email=email, first_user=first)

    if db.query(models.User).filter(models.User.username == username).first():
        return _render(request, "register.html", status=409, error="That username is taken.",
                       username=username, email=email, first_user=first)
    if db.query(models.User).filter(models.User.email == email).first():
        return _render(request, "register.html", status=409, error="That email is already registered.",
                       username=username, email=email, first_user=first)

    role = "admin" if first else "viewer"
    user = models.User(username=username, email=email, password_hash=sec.hash_password(password),
                       role=role, api_token=sec.new_api_token(), active=True)
    db.add(user)
    db.commit()
    sec.audit(db, username, "register", f"role={role}", _client_ip(request))
    resp = RedirectResponse("/", status_code=302)
    sec.set_session_cookie(resp, user)
    return resp


@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    u, _ = sec._principal(request, db)
    if u:
        sec.audit(db, u.username, "logout", "", _client_ip(request))
    resp = RedirectResponse("/login", status_code=302)
    sec.clear_session_cookie(resp)
    return resp
