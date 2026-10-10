"""
authentication.py - register / verify OTP / login / logout for the Fire Detection API.

Flow
----
1. POST /auth/register     -> account is created with status = 0 (unverified), role = viewer,
                              a 6-digit OTP is e-mailed to the user's Gmail address.
2. POST /auth/verify-otp   -> correct OTP sets status = 1. Only then can the account log in.
3. POST /auth/login        -> returns a session token (also set as an HttpOnly cookie).
4. POST /auth/logout       -> the session is deleted on the server (the token stops working).
5. Forgot password:
   POST /auth/forgot-password -> e-mails a 6-digit reset code to a verified account's Gmail
                                 (call it again to resend; 60 s cooldown)
   POST /auth/reset-password  -> correct code + new password -> password changed and
                                 every existing session of that user is logged out

Rules
-----
* username and password may contain ONLY letters and digits (A-Z, a-z, 0-9).
* email must be a @gmail.com address (the OTP is sent there).
* Passwords are stored as salted PBKDF2-SHA256 hashes, OTPs and session tokens as hashes.

Environment variables (.env)
----------------------------
GMAIL_ADDRESS=yourbot@gmail.com          # account that SENDS the OTP e-mails
GMAIL_APP_PASSWORD=abcd efgh ijkl mnop   # Google "App password" (needs 2-step verification)
ADMIN_USERNAME=admin1                    # optional: first admin, created at startup if none exists
ADMIN_PASSWORD=ChangeMe12345
ADMIN_EMAIL=owner@gmail.com
AUTH_COOKIE_SECURE=false                 # set true when served over HTTPS
AUTH_DEV_MODE=false                      # true = print OTP in the server log instead of e-mailing

Authorization (roles / capabilities) lives in authorization.py.

Run it on its own (test mode)
-----------------------------
    python authentication.py

* Database: users.db next to this file (no database.py / main.py needed).
* Opens an API on http://localhost:8000 and serves auth.html at "/" if that file is next to it.
* If Gmail is not configured, DEV MODE is switched on and the OTP is printed in this terminal.
* If ADMIN_* are not set, a TEST admin is created: admin1 / Admin12345  (change it for real use!)
"""
import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import sys
import threading
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime
from email.message import EmailMessage

from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from starlette.requests import HTTPConnection

load_dotenv()
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- config
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.getenv("AUTH_DB_NAME", os.path.join(BASE_DIR, "users.db"))

STATUS_UNVERIFIED = 0
STATUS_ACTIVE = 1
DEFAULT_ROLE = "viewer"

SESSION_COOKIE = "fg_session"
SESSION_TTL_SECONDS = 12 * 3600
OTP_TTL_SECONDS = 10 * 60
OTP_RESEND_COOLDOWN_SECONDS = 60
OTP_MAX_ATTEMPTS = 5
LOGIN_MAX_FAILURES = 5
LOGIN_LOCK_SECONDS = 5 * 60
PBKDF2_ITERATIONS = 600_000

COOKIE_SECURE = os.getenv("AUTH_COOKIE_SECURE", "false").lower() == "true"
DEV_MODE = os.getenv("AUTH_DEV_MODE", "false").lower() == "true"

# --------------------------------------------------------------------------- database
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer','operator','admin')),
    status        INTEGER NOT NULL DEFAULT 0 CHECK (status IN (0,1)),
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otp_codes (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    salt       TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    expires_at REAL NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    last_sent  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS password_resets (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    salt       TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    expires_at REAL NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    last_sent  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    ip         TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username  TEXT,
    action    TEXT NOT NULL,
    detail    TEXT,
    ip        TEXT
);
"""


@contextmanager
def get_db():
    """SQLite connection that commits on success and rolls back on any exception."""
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def audit(action, username=None, detail=None, ip=None):
    """Append an entry to the audit log (never raises)."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_log (timestamp, username, action, detail, ip) VALUES (?,?,?,?,?)",
                (_now_str(), username, action, detail, ip),
            )
    except Exception:
        logger.exception("Could not write audit log entry '%s'", action)


# --------------------------------------------------------------------------- validation
_ALNUM = re.compile(r"[A-Za-z0-9]+")
_GMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@gmail\.com", re.IGNORECASE)


def _bad(msg):
    return HTTPException(status_code=422, detail=msg)


def validate_username(username: str):
    if not (4 <= len(username) <= 32):
        raise _bad("Username must be 4-32 characters.")
    if not _ALNUM.fullmatch(username):
        raise _bad("Username may contain only letters and digits (no spaces or special symbols).")


def validate_password(password: str):
    if not (8 <= len(password) <= 64):
        raise _bad("Password must be 8-64 characters.")
    if not _ALNUM.fullmatch(password):
        raise _bad("Password may contain only letters and digits (no spaces or special symbols).")
    if not (re.search(r"[A-Za-z]", password) and re.search(r"[0-9]", password)):
        raise _bad("Password must contain at least one letter and one digit.")


def validate_email(email: str):
    if len(email) > 254 or not _GMAIL.fullmatch(email):
        raise _bad("Please use a valid Gmail address (example@gmail.com).")


# --------------------------------------------------------------------------- passwords
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except Exception:
        return False


# Used so that "unknown user" and "wrong password" take the same time.
_DUMMY_HASH = hash_password("DummyPassword123")


# --------------------------------------------------------------------------- OTP
def _otp_digest(salt: str, otp: str) -> str:
    return hashlib.sha256(f"{salt}:{otp}".encode()).hexdigest()


def _store_otp(conn, user_id: int, table: str = "otp_codes") -> str:
    """Create a fresh code for the user inside the open transaction and return it.

    table is "otp_codes" (account verification) or "password_resets" (forgot password).
    """
    assert table in ("otp_codes", "password_resets")
    otp = f"{secrets.randbelow(10 ** 6):06d}"
    salt = secrets.token_hex(8)
    now = time.time()
    conn.execute(
        f"INSERT OR REPLACE INTO {table} (user_id, salt, code_hash, expires_at, attempts, last_sent) "
        "VALUES (?,?,?,?,0,?)",
        (user_id, salt, _otp_digest(salt, otp), now + OTP_TTL_SECONDS, now),
    )
    return otp


def _send_otp_email(to_email: str, otp: str, purpose: str = "verify"):
    sender = os.getenv("GMAIL_ADDRESS")
    app_password = (os.getenv("GMAIL_APP_PASSWORD") or "").replace(" ", "")

    if not sender or not app_password:
        if DEV_MODE:
            logger.warning("[DEV MODE] OTP for %s is %s", to_email, otp)
            return
        raise RuntimeError("GMAIL_ADDRESS / GMAIL_APP_PASSWORD are not configured")

    msg = EmailMessage()
    msg["Subject"] = ("Your Fire Guard password reset code" if purpose == "reset"
                      else "Your Fire Guard verification code")
    msg["From"] = sender
    msg["To"] = to_email
    if purpose == "reset":
        msg.set_content(
            f"Your password reset code is: {otp}\n\n"
            f"It expires in {OTP_TTL_SECONDS // 60} minutes. "
            "If you did not ask to reset your password, ignore this e-mail - your password is unchanged."
        )
    else:
        msg.set_content(
            f"Your verification code is: {otp}\n\n"
            f"It expires in {OTP_TTL_SECONDS // 60} minutes. "
            "If you did not create an account, you can ignore this e-mail."
        )
    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as smtp:
        smtp.starttls()
        smtp.login(sender, app_password)
        smtp.send_message(msg)


# --------------------------------------------------------------------------- login throttle
class _LoginThrottle:
    """Blocks an (ip, username) pair for a while after too many failed logins."""

    def __init__(self):
        self._fails = {}
        self._lock = threading.Lock()

    def _prune(self, key, now):
        self._fails[key] = [t for t in self._fails.get(key, []) if now - t < LOGIN_LOCK_SECONDS]

    def check(self, key):
        now = time.time()
        with self._lock:
            self._prune(key, now)
            if len(self._fails[key]) >= LOGIN_MAX_FAILURES:
                raise HTTPException(status_code=429,
                                    detail="Too many failed attempts. Try again in a few minutes.")

    def fail(self, key):
        with self._lock:
            self._fails.setdefault(key, []).append(time.time())

    def clear(self, key):
        with self._lock:
            self._fails.pop(key, None)


_throttle = _LoginThrottle()


# --------------------------------------------------------------------------- sessions
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _extract_token(conn: HTTPConnection):
    """Token from 'Authorization: Bearer ...' or from the session cookie.

    The cookie makes <img src="/video_feed/1"> and WebSocket connections work,
    because browsers cannot attach custom headers to those.
    """
    auth = conn.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return conn.cookies.get(SESSION_COOKIE)


def get_current_user(request: HTTPConnection) -> dict:
    """FastAPI dependency: the logged-in, verified user (works for HTTP and WebSocket)."""
    token = _extract_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    with get_db() as db:
        row = db.execute(
            "SELECT u.id, u.username, u.email, u.role, u.status, s.expires_at "
            "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
            (_token_hash(token),),
        ).fetchone()

    if row is None or row["expires_at"] < time.time() or row["status"] != STATUS_ACTIVE:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    return {"id": row["id"], "username": row["username"], "email": row["email"], "role": row["role"]}


# --------------------------------------------------------------------------- startup
def init_auth_db():
    """Create tables and, if no admin exists yet, seed one from ADMIN_* env variables."""
    with get_db() as conn:
        conn.executescript(SCHEMA)

    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    email = (os.getenv("ADMIN_EMAIL") or "").strip().lower()

    with get_db() as conn:
        has_admin = conn.execute(
            "SELECT 1 FROM users WHERE role = 'admin' AND status = 1 LIMIT 1").fetchone()
        if has_admin:
            return
        if not (username and password and email):
            logger.warning("No admin account exists. Set ADMIN_USERNAME, ADMIN_PASSWORD and "
                           "ADMIN_EMAIL in .env to create the first admin.")
            return
        try:
            validate_username(username)
            validate_password(password)
            validate_email(email)
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role, status, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (username, email, hash_password(password), "admin", STATUS_ACTIVE, _now_str()),
            )
            logger.info("First admin account '%s' created.", username)
        except HTTPException as e:
            logger.error("ADMIN_* values are invalid: %s", e.detail)
        except sqlite3.IntegrityError:
            logger.error("Cannot create the first admin: username or e-mail is already taken.")


# --------------------------------------------------------------------------- routes
router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterBody(BaseModel):
    username: str
    email: str
    password: str


class VerifyBody(BaseModel):
    email: str
    otp: str


class ResendBody(BaseModel):
    email: str


class LoginBody(BaseModel):
    username: str
    password: str


def _ip(request: Request):
    return request.client.host if request.client else None


@router.post("/register", status_code=201)
def register(body: RegisterBody, request: Request):
    """Create an UNVERIFIED account (status 0, role viewer) and e-mail the OTP."""
    username = body.username
    email = body.email.strip().lower()
    validate_username(username)
    validate_password(body.password)
    validate_email(email)

    pw_hash = hash_password(body.password)

    with get_db() as conn:
        # Free up names held by accounts that never verified
        conn.execute("DELETE FROM users WHERE status = 0 "
                     "AND created_at < datetime('now', 'localtime', '-1 day')")
        try:
            cur = conn.execute(
                "INSERT INTO users (username, email, password_hash, role, status, created_at) "
                "VALUES (?,?,?,?,?,?)",
                (username, email, pw_hash, DEFAULT_ROLE, STATUS_UNVERIFIED, _now_str()),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Username or e-mail is already registered.")
        user_id = cur.lastrowid
        otp = _store_otp(conn, user_id)

    # The e-mail is sent after the DB transaction is closed (SMTP can be slow).
    try:
        _send_otp_email(email, otp)
    except Exception:
        logger.exception("Could not send OTP e-mail to %s", email)
        with get_db() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        raise HTTPException(status_code=502,
                            detail="Could not send the verification e-mail. Please try again later.")

    audit("register", username, f"email={email}", _ip(request))
    return {"status": "ok",
            "message": "Account created. Enter the OTP sent to your Gmail to activate it."}


@router.post("/verify-otp")
def verify_otp(body: VerifyBody, request: Request):
    """Correct OTP -> status becomes 1 and the account can be used."""
    email = body.email.strip().lower()
    otp = body.otp.strip()
    generic = HTTPException(status_code=400, detail="Invalid or expired code.")
    error = None
    username = None

    with get_db() as conn:
        user = conn.execute("SELECT id, username, status FROM users WHERE email = ?", (email,)).fetchone()
        rec = None
        if user is not None and user["status"] == STATUS_UNVERIFIED:
            rec = conn.execute("SELECT * FROM otp_codes WHERE user_id = ?", (user["id"],)).fetchone()

        if user is None or rec is None or rec["expires_at"] < time.time():
            error = generic
        elif rec["attempts"] >= OTP_MAX_ATTEMPTS:
            error = HTTPException(status_code=429,
                                  detail="Too many wrong codes. Please request a new one.")
        elif not (otp.isdigit() and hmac.compare_digest(_otp_digest(rec["salt"], otp), rec["code_hash"])):
            conn.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE user_id = ?", (user["id"],))
            error = generic
        else:
            conn.execute("UPDATE users SET status = ? WHERE id = ?", (STATUS_ACTIVE, user["id"]))
            conn.execute("DELETE FROM otp_codes WHERE user_id = ?", (user["id"],))
            username = user["username"]

    # raised after the 'with' so the attempt counter is committed, not rolled back
    if error is not None:
        raise error

    audit("verify_otp", username, None, _ip(request))
    return {"status": "ok", "message": "Account verified. You can log in now."}


@router.post("/resend-otp")
def resend_otp(body: ResendBody, request: Request):
    """Send a new OTP to an unverified account (same reply whether or not the e-mail exists)."""
    email = body.email.strip().lower()
    reply = {"status": "ok", "message": "If the account exists and is unverified, a new code was sent."}
    otp = None

    with get_db() as conn:
        user = conn.execute("SELECT id, status FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or user["status"] != STATUS_UNVERIFIED:
            return reply
        rec = conn.execute("SELECT last_sent FROM otp_codes WHERE user_id = ?", (user["id"],)).fetchone()
        if rec is not None and time.time() - rec["last_sent"] < OTP_RESEND_COOLDOWN_SECONDS:
            wait = int(OTP_RESEND_COOLDOWN_SECONDS - (time.time() - rec["last_sent"])) + 1
            raise HTTPException(status_code=429, detail=f"Please wait {wait}s before requesting a new code.")
        otp = _store_otp(conn, user["id"])

    try:
        _send_otp_email(email, otp)
    except Exception:
        logger.exception("Could not send OTP e-mail to %s", email)
        raise HTTPException(status_code=502, detail="Could not send the verification e-mail.")
    audit("resend_otp", None, f"email={email}", _ip(request))
    return reply


@router.post("/login")
def login(body: LoginBody, request: Request, response: Response):
    ip = _ip(request)
    key = f"{ip}|{body.username.lower()}"
    _throttle.check(key)

    invalid = HTTPException(status_code=401, detail="Invalid username or password.")

    # Anything with special symbols can never be a real account -> same generic error
    row = None
    if _ALNUM.fullmatch(body.username) and len(body.username) <= 32:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, role, status FROM users WHERE username = ?",
                (body.username,),
            ).fetchone()

    password_ok = verify_password(body.password[:128], row["password_hash"] if row else _DUMMY_HASH)
    if row is None or not password_ok:
        _throttle.fail(key)
        audit("login_failed", body.username[:32], None, ip)
        raise invalid

    if row["status"] != STATUS_ACTIVE:
        raise HTTPException(status_code=403,
                            detail="Account is not verified yet. Enter the OTP sent to your Gmail.")

    _throttle.clear(key)
    token = secrets.token_urlsafe(32)
    now = time.time()
    with get_db() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, ip) VALUES (?,?,?,?,?)",
            (_token_hash(token), row["id"], now, now + SESSION_TTL_SECONDS, ip),
        )

    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS,
                        httponly=True, samesite="lax", secure=COOKIE_SECURE, path="/")
    audit("login", row["username"], None, ip)
    return {
        "status": "ok",
        "token": token,  # for API clients; browsers can rely on the cookie
        "expires_in": SESSION_TTL_SECONDS,
        "user": {"id": row["id"], "username": row["username"], "role": row["role"]},
    }


@router.post("/logout")
def logout(request: Request, response: Response):
    """Delete the session on the server and clear the cookie."""
    token = _extract_token(request)
    if token:
        username = None
        with get_db() as conn:
            row = conn.execute(
                "SELECT u.username FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash = ?", (_token_hash(token),)).fetchone()
            if row:
                username = row["username"]
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
        if username:
            audit("logout", username, None, _ip(request))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok", "message": "Logged out"}


# --------------------------------------------------------------------------- forgot password
class ForgotBody(BaseModel):
    email: str


class ResetBody(BaseModel):
    email: str
    otp: str
    new_password: str


@router.post("/forgot-password")
def forgot_password(body: ForgotBody, request: Request):
    """E-mail a reset code. Same reply whether or not the account exists (no user enumeration).

    Calling it again is the "resend" - a new code replaces the old one, at most once per minute.
    """
    email = body.email.strip().lower()
    validate_email(email)
    reply = {"status": "ok",
             "message": "If this Gmail belongs to a verified account, a reset code was sent."}
    code = None
    username = None

    with get_db() as conn:
        user = conn.execute("SELECT id, username, status FROM users WHERE email = ?", (email,)).fetchone()
        if user is None or user["status"] != STATUS_ACTIVE:
            return reply
        rec = conn.execute("SELECT last_sent FROM password_resets WHERE user_id = ?",
                           (user["id"],)).fetchone()
        if rec is not None and time.time() - rec["last_sent"] < OTP_RESEND_COOLDOWN_SECONDS:
            return reply  # too soon: silently ignore so the reply reveals nothing
        username = user["username"]
        code = _store_otp(conn, user["id"], "password_resets")

    try:
        _send_otp_email(email, code, "reset")
    except Exception:
        logger.exception("Could not send reset e-mail to %s", email)
        raise HTTPException(status_code=502, detail="Could not send the reset e-mail. Please try again later.")

    audit("forgot_password", username, None, _ip(request))
    return reply


@router.post("/reset-password")
def reset_password(body: ResetBody, request: Request):
    """Correct code + valid new password -> password changed, all sessions of the user removed."""
    email = body.email.strip().lower()
    otp = body.otp.strip()
    validate_email(email)
    validate_password(body.new_password)
    new_hash = hash_password(body.new_password)

    generic = HTTPException(status_code=400, detail="Invalid or expired code.")
    error = None
    username = None

    with get_db() as conn:
        user = conn.execute("SELECT id, username, status FROM users WHERE email = ?", (email,)).fetchone()
        rec = None
        if user is not None and user["status"] == STATUS_ACTIVE:
            rec = conn.execute("SELECT * FROM password_resets WHERE user_id = ?", (user["id"],)).fetchone()

        if rec is None or rec["expires_at"] < time.time():
            error = generic
        elif rec["attempts"] >= OTP_MAX_ATTEMPTS:
            error = HTTPException(status_code=429, detail="Too many wrong codes. Please request a new one.")
        elif not (otp.isdigit() and hmac.compare_digest(_otp_digest(rec["salt"], otp), rec["code_hash"])):
            conn.execute("UPDATE password_resets SET attempts = attempts + 1 WHERE user_id = ?", (user["id"],))
            error = generic
        else:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
            conn.execute("DELETE FROM password_resets WHERE user_id = ?", (user["id"],))
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))  # log out everywhere
            username = user["username"]

    # raised after the 'with' so the attempt counter is committed, not rolled back
    if error is not None:
        raise error

    audit("password_reset", username, None, _ip(request))
    return {"status": "ok", "message": "Password changed. Please log in with the new password."}


# --------------------------------------------------------------------------- standalone app
@asynccontextmanager
async def lifespan(_app):
    init_auth_db()
    yield


app = FastAPI(title="Auth test", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000",
                   "http://127.0.0.1:3000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)

_HTML_PAGE = os.path.join(BASE_DIR, "auth.html")


@app.get("/")
def index():
    """Serves auth.html (same origin as the API, so cookies just work)."""
    if os.path.exists(_HTML_PAGE):
        return FileResponse(_HTML_PAGE)
    return {"status": "ok", "message": "Auth API is running. Put auth.html next to this file for the UI."}


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    # When run as a script this module is called "__main__"; register it under its real name so
    # authorization.py's `from authentication import ...` reuses THIS module instead of loading a copy.
    sys.modules["authentication"] = sys.modules[__name__]

    # ---- test conveniences -------------------------------------------------------------
    if not (os.getenv("GMAIL_ADDRESS") and os.getenv("GMAIL_APP_PASSWORD")):
        DEV_MODE = True  # print the OTP in this terminal instead of e-mailing it
        print("[test] Gmail not configured -> DEV MODE: OTP codes are printed here.")

    if not os.getenv("ADMIN_USERNAME"):
        os.environ["ADMIN_USERNAME"] = "admin1"
        os.environ["ADMIN_PASSWORD"] = "Admin12345"
        os.environ["ADMIN_EMAIL"] = "admin@gmail.com"
        print("[test] No ADMIN_* set -> test admin: admin1 / Admin12345  (do not use in production)")

    # ---- roles / capabilities routes (/auth/me, /admin/...) ----------------------------
    try:
        import authorization
        app.include_router(authorization.router)
    except ImportError:
        print("[test] authorization.py not found next to this file -> /auth/me and /admin/* are disabled.")

    print(f"[test] Database: {DB_NAME}")
    print("[test] Open http://localhost:8000  (use 'localhost', not 127.0.0.1)")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")