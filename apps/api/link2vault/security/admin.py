"""Same-origin and double-submit CSRF protection for administrator routes."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

CSRF_COOKIE_NAME = "l2v_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_MAX_AGE_SECONDS = 12 * 60 * 60
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_REJECTED = {
    "detail": {
        "code": "CSRF_REJECTED",
        "message": "Admin request rejected",
    }
}


def _origin_tuple(value: str) -> tuple[str, str, int | None] | None:
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            return None
        default_port = 443 if parsed.scheme == "https" else 80
        return (parsed.scheme, parsed.hostname.casefold(), parsed.port or default_port)
    except ValueError:
        return None


class AdminSecurity:
    """Issue and validate signed CSRF tokens for one public origin."""

    def __init__(self, public_base_url: str, signing_key: bytes) -> None:
        origin = _origin_tuple(public_base_url)
        if origin is None:
            raise ValueError("public_base_url must be an absolute HTTP(S) origin")
        if len(signing_key) < 16:
            raise ValueError("CSRF signing key must contain at least 16 bytes")
        self.origin = origin
        self._signing_key = signing_key

    def issue_token(self) -> str:
        """Create a signed token with a random nonce and current timestamp."""

        payload = f"{secrets.token_urlsafe(32)}.{int(time.time())}"
        signature = hmac.new(
            self._signing_key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{payload}.{signature}"

    def valid_token(self, token: str) -> bool:
        """Validate signature and maximum age without raising on malformed input."""

        try:
            nonce, raw_timestamp, supplied_signature = token.split(".", maxsplit=2)
            timestamp = int(raw_timestamp)
        except (TypeError, ValueError):
            return False
        if not nonce or timestamp > int(time.time()):
            return False
        if int(time.time()) - timestamp > CSRF_MAX_AGE_SECONDS:
            return False
        payload = f"{nonce}.{raw_timestamp}"
        expected_signature = hmac.new(
            self._signing_key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(supplied_signature, expected_signature)


class AdminCsrfMiddleware(BaseHTTPMiddleware):
    """Protect unsafe administrator methods and leave ingest routes untouched."""

    def __init__(self, app: object, security: AdminSecurity) -> None:
        super().__init__(app)
        self._security = security

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        requires_csrf = request.url.path.startswith("/admin/") and (
            request.method in _UNSAFE_METHODS
        )
        if not requires_csrf:
            return await call_next(request)
        if _origin_tuple(request.headers.get("origin", "")) != self._security.origin:
            return JSONResponse(_REJECTED, status_code=403)
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
        header_token = request.headers.get(CSRF_HEADER_NAME, "")
        if (
            not cookie_token
            or not header_token
            or not hmac.compare_digest(cookie_token, header_token)
            or not self._security.valid_token(cookie_token)
        ):
            return JSONResponse(_REJECTED, status_code=403)
        return await call_next(request)
