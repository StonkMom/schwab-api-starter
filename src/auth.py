"""
Schwab OAuth 2.0 flow.

Schwab's individual-developer auth is a standard 3-legged OAuth with a twist:
the callback URL must be HTTPS, even if it's localhost. We spin up a tiny
self-signed HTTPS server on 127.0.0.1:8182 to catch the redirect.

Token lifetimes (as of Schwab Trader API v1):
  - access_token:  30 minutes
  - refresh_token: 7 days (after which the user must re-auth interactively)

Usage:
    python -m src.auth            # interactive login, writes tokens.json
    # or, from code:
    from src.auth import SchwabAuth
    auth = SchwabAuth.from_env()
    access_token = auth.get_valid_access_token()
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass, asdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

SCHWAB_AUTH_URL = "https://api.schwabapi.com/v1/oauth/authorize"
SCHWAB_TOKEN_URL = "https://api.schwabapi.com/v1/oauth/token"

log = logging.getLogger(__name__)


@dataclass
class Tokens:
    access_token: str
    refresh_token: str
    expires_at: float   # unix seconds
    refresh_expires_at: float

    @property
    def is_access_expired(self) -> bool:
        # refresh 60s before actual expiry to be safe
        return time.time() > (self.expires_at - 60)

    @property
    def is_refresh_expired(self) -> bool:
        return time.time() > self.refresh_expires_at


class _CodeCatcher(BaseHTTPRequestHandler):
    """One-shot HTTP handler that captures the ?code= param from the callback."""
    captured_code: Optional[str] = None
    captured_state: Optional[str] = None

    def do_GET(self):  # noqa: N802 (stdlib signature)
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        _CodeCatcher.captured_code = qs.get("code", [None])[0]
        _CodeCatcher.captured_state = qs.get("state", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><body><h2>Schwab auth complete.</h2>"
            b"<p>You can close this tab and return to the terminal.</p>"
            b"</body></html>"
        )

    def log_message(self, format, *args):  # silence default access logs
        pass


def _make_selfsigned_cert(certfile: Path) -> None:
    """Generate a throwaway self-signed cert for the localhost callback."""
    # Generation needs the `cryptography` library. Kept as a lazy import so the
    # rest of the module loads even if it isn't installed yet.
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as _dt
    except ImportError:
        print(
            "The `cryptography` package is required for the one-shot HTTPS callback.\n"
            "Install it with: pip install cryptography",
            file=sys.stderr,
        )
        raise

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )
    # Use timezone-aware UTC datetimes; `datetime.utcnow()` is deprecated
    # in Python 3.12+ and removed in future versions.
    _now_utc = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now_utc)
        .not_valid_after(_now_utc + _dt.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                          x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with open(certfile, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        f.write(cert.public_bytes(serialization.Encoding.PEM))


class SchwabAuth:
    def __init__(
        self,
        app_key: str,
        app_secret: str,
        callback_url: str,
        token_path: Path,
    ):
        self.app_key = app_key
        self.app_secret = app_secret
        self.callback_url = callback_url
        self.token_path = Path(token_path)
        self._tokens: Optional[Tokens] = None
        # Thread lock guarding _refresh. If your bot fetches data in parallel
        # (e.g. a ThreadPoolExecutor for bar fetches) and two fetches both hit
        # a 401 at the same time, they'd race on _refresh: both POST to Schwab,
        # both write tokens.json, last-write-wins. If Schwab rotated the
        # refresh_token in the first response, the second response could
        # overwrite it and orphan the newer token. The lock serializes the
        # refresh; the second caller finds tokens already valid and returns.
        self._refresh_lock = threading.Lock()
        # Optional callback fired BEFORE login_interactive opens a browser.
        # Wire this to your alerter so you get the "refresh token expired"
        # notification on your phone before the trading loop blocks for up to
        # 5 minutes waiting on the OAuth callback. Signature:
        # `callback(reason: str) -> None`, called with reason in
        # {"refresh_expired", "no_tokens"}. Exceptions are swallowed so an
        # alert failure never blocks auth.
        self._on_interactive_login_required = None
        self._load_tokens_if_present()

    def set_on_interactive_login_required(self, callback) -> None:
        """Wire a callback fired right before login_interactive opens
        the browser. See __init__ docstring."""
        self._on_interactive_login_required = callback

    def refresh_token_seconds_remaining(self) -> Optional[float]:
        """Seconds until the loaded refresh token expires, or None if no
        tokens are loaded. Negative if already past expiry. Use this for a
        periodic token-age check so you can alert yourself before the 7-day
        refresh window runs out (and re-auth on your schedule, not in the
        middle of a trading day)."""
        if not self._tokens:
            return None
        return self._tokens.refresh_expires_at - time.time()

    @classmethod
    def from_env(cls) -> "SchwabAuth":
        load_dotenv()
        key = os.getenv("SCHWAB_APP_KEY")
        secret = os.getenv("SCHWAB_APP_SECRET")
        cb = os.getenv("SCHWAB_CALLBACK_URL", "https://127.0.0.1:8182/")
        token_path = os.getenv("SCHWAB_TOKEN_PATH", "./tokens.json")
        if not key or not secret:
            raise RuntimeError(
                "SCHWAB_APP_KEY and SCHWAB_APP_SECRET must be set in .env. "
                "Waiting on developer approval? Copy .env.example to .env and leave "
                "placeholders until your keys arrive."
            )
        return cls(key, secret, cb, Path(token_path))

    # -- persistence -------------------------------------------------------
    def _load_tokens_if_present(self) -> None:
        if self.token_path.exists():
            try:
                data = json.loads(self.token_path.read_text())
                # Filter to known dataclass fields so a future Schwab response
                # adding a new key doesn't TypeError out of `Tokens(**data)`
                # and force a re-auth.
                from dataclasses import fields
                known = {f.name for f in fields(Tokens)}
                self._tokens = Tokens(**{k: v for k, v in data.items() if k in known})
            except Exception as e:
                # Surface tokens.json parse failures in the log instead of
                # swallowing them. A corrupt/truncated tokens.json otherwise
                # triggers interactive login at startup with no diagnostic,
                # making the cause hard to find. Auth proceeds to interactive
                # login regardless; this log just explains why.
                log.warning(
                    "tokens.json failed to parse, forcing interactive login: %s", e,
                )
                self._tokens = None

    def _save_tokens(self) -> None:
        # Atomic write: write to .tmp then rename. Schwab rotates the
        # refresh_token on every refresh — the OLD one is dead the moment
        # the response with the NEW one arrives. A crash mid-write would
        # leave tokens.json empty/partial, requiring interactive re-auth
        # (loses a trading day if it happens overnight).
        if not self._tokens:
            return
        tmp = self.token_path.with_suffix(self.token_path.suffix + ".tmp")
        tmp.write_text(json.dumps(asdict(self._tokens), indent=2))
        tmp.replace(self.token_path)

    # -- interactive login -------------------------------------------------
    def login_interactive(self) -> Tokens:
        """Open a browser, catch the code, exchange it for tokens."""
        state = secrets.token_urlsafe(16)
        params = {
            "response_type": "code",
            "client_id": self.app_key,
            "redirect_uri": self.callback_url,
            "state": state,
        }
        url = f"{SCHWAB_AUTH_URL}?{urllib.parse.urlencode(params)}"

        # Derive the listen port from callback_url instead of hardcoding 8182.
        # If you set SCHWAB_CALLBACK_URL to a different port, hardcoding would
        # tell Schwab to redirect there but listen on 8182 — a silent
        # auth-flow failure with no obvious cause.
        parsed_cb = urllib.parse.urlparse(self.callback_url)
        port = parsed_cb.port or 8182

        # start a temporary HTTPS server
        cert_path = Path("./.schwab_cb_cert.pem")
        if not cert_path.exists():
            _make_selfsigned_cert(cert_path)

        # Port-busy guard: a leftover Python process from a previous auth
        # attempt that didn't shut down cleanly (window closed without
        # Ctrl+C, etc.) can hold the callback port in LISTEN state. If we
        # don't detect that here, HTTPServer() raises a cryptic OSError, OR
        # — on some Windows configurations — silently binds to the same
        # port while the OLD process keeps receiving callbacks. You then
        # complete the browser flow but tokens.json never updates, because
        # the OAuth code went to the ghost process. Detect it early and say
        # what to do.
        import socket as _socket
        _probe = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            _probe.bind(("127.0.0.1", port))
        except OSError:
            print("", file=sys.stderr)
            print("=" * 70, file=sys.stderr)
            if sys.platform == "win32":
                kill_hint = "    Stop-Process -Name python -Force   # PowerShell"
            else:
                kill_hint = f"    lsof -ti :{port} | xargs kill       # Mac / Linux"
            print(
                "  Auth won't start: a previous Python process is still",
                f"  using port {port} (the OAuth callback port).",
                "",
                "  This usually means an earlier auth attempt didn't shut",
                "  down cleanly — maybe you closed the browser window",
                "  before completing the Schwab login.",
                "",
                "  To fix, kill the old process:",
                "",
                kill_hint,
                "",
                "  Then run auth again:",
                "",
                "    python -m src.auth",
                sep="\n",
                file=sys.stderr,
            )
            print("=" * 70, file=sys.stderr)
            print("", file=sys.stderr)
            _probe.close()
            raise SystemExit(1)
        _probe.close()

        server = HTTPServer(("127.0.0.1", port), _CodeCatcher)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()

        print(f"Opening browser for Schwab login...\n  {url}")
        webbrowser.open(url)
        print(
            f"Your browser will warn about a self-signed cert on 127.0.0.1:{port} — "
            "that's expected. Accept the warning to complete the redirect."
        )

        # wait up to 5 minutes for the code to land
        deadline = time.time() + 300
        while _CodeCatcher.captured_code is None and time.time() < deadline:
            time.sleep(0.25)
        server.shutdown()

        if not _CodeCatcher.captured_code:
            raise RuntimeError("Timed out waiting for OAuth callback.")
        if _CodeCatcher.captured_state != state:
            raise RuntimeError("OAuth state mismatch — possible CSRF. Aborting.")

        return self._exchange_code(_CodeCatcher.captured_code)

    def _basic_auth_header(self) -> dict:
        raw = f"{self.app_key}:{self.app_secret}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    def _exchange_code(self, code: str) -> Tokens:
        resp = requests.post(
            SCHWAB_TOKEN_URL,
            headers={
                **self._basic_auth_header(),
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.callback_url,
            },
            timeout=15,
        )
        resp.raise_for_status()
        payload = resp.json()
        now = time.time()
        self._tokens = Tokens(
            access_token=payload["access_token"],
            refresh_token=payload["refresh_token"],
            expires_at=now + payload.get("expires_in", 1800),
            # Schwab refresh tokens are valid 7 days from issue
            refresh_expires_at=now + 7 * 24 * 3600,
        )
        self._save_tokens()
        return self._tokens

    def _refresh(self) -> Tokens:
        # Serialize refresh across threads. The second caller checks whether
        # the access token is already valid (set by the first caller) and
        # returns immediately without hitting Schwab again.
        with self._refresh_lock:
            if self._tokens and not self._tokens.is_access_expired:
                return self._tokens
            return self._do_refresh()

    def _do_refresh(self) -> Tokens:
        if not self._tokens:
            raise RuntimeError("No tokens loaded; run login_interactive() first.")
        resp = requests.post(
            SCHWAB_TOKEN_URL,
            headers={
                **self._basic_auth_header(),
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "refresh_token",
                "refresh_token": self._tokens.refresh_token,
            },
            timeout=15,
        )
        resp.raise_for_status()
        payload = resp.json()
        now = time.time()
        # Refresh-token rotation: Schwab may or may not return a new
        # refresh_token in the response. If they DO rotate it, the new
        # token starts a fresh 7-day clock — reset the local expiry to
        # `now + 7 days`. Preserving the OLD refresh_expires_at when a new
        # token was issued causes premature interactive re-auth: the
        # original 7-day window elapses even though you hold a valid
        # (rotated) token.
        new_refresh_token = payload.get("refresh_token", self._tokens.refresh_token)
        if new_refresh_token != self._tokens.refresh_token:
            # Rotated: reset 7-day clock from now.
            new_refresh_expires_at = now + 7 * 24 * 3600
        else:
            # Same token returned (no rotation): keep original expiry.
            new_refresh_expires_at = self._tokens.refresh_expires_at
        self._tokens = Tokens(
            access_token=payload["access_token"],
            refresh_token=new_refresh_token,
            expires_at=now + payload.get("expires_in", 1800),
            refresh_expires_at=new_refresh_expires_at,
        )
        self._save_tokens()
        return self._tokens

    # -- public API --------------------------------------------------------
    def get_valid_access_token(self) -> str:
        if self._tokens is None:
            self._notify_interactive_required("no_tokens")
            self.login_interactive()
        assert self._tokens is not None
        if self._tokens.is_refresh_expired:
            print("Refresh token expired — re-authenticating interactively.")
            self._notify_interactive_required("refresh_expired")
            self.login_interactive()
        elif self._tokens.is_access_expired:
            self._refresh()
        return self._tokens.access_token

    def _notify_interactive_required(self, reason: str) -> None:
        """Fire the registered callback (if any) before blocking on the
        OAuth browser flow. See __init__ docstring. Exceptions are
        swallowed so an alerter failure never blocks the auth path."""
        cb = self._on_interactive_login_required
        if cb is None:
            return
        try:
            cb(reason)
        except Exception:
            pass


if __name__ == "__main__":
    auth = SchwabAuth.from_env()
    token = auth.get_valid_access_token()
    print(f"Got access token (first 12 chars): {token[:12]}...")
    print(f"Tokens saved to: {auth.token_path}")
