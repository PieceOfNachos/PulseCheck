"""JWT verification for the agent API.

Tokens are issued by the auth service (HS256, shared ``JWT_SECRET``) with the payload
``{id, email, iat, exp}``.
"""

from __future__ import annotations

import jwt
from fastapi import HTTPException

from app.config import settings


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"}
    )


def user_id_from_auth_header(header: str | None) -> str:
    """Return the user id from an ``Authorization: Bearer <jwt>`` header or raise 401."""
    if not header:
        raise _unauthorized("Missing Authorization header")

    scheme, _, token = header.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized("Authorization header must be 'Bearer <token>'")

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            options={"require": ["exp"]},
        )
    except jwt.ExpiredSignatureError:
        raise _unauthorized("Token expired") from None
    except jwt.InvalidTokenError:
        raise _unauthorized("Invalid token") from None

    user_id = payload.get("id")
    if user_id is None or str(user_id) == "":
        raise _unauthorized("Token has no user id")
    return str(user_id)
