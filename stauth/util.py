from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

import bcrypt
import jwt


def _get_jwt_expiry(days_to_expiry: int, expiry_datetime: Optional[datetime]) -> datetime:
    expiry = datetime.now(tz=timezone.utc) + timedelta(days=days_to_expiry)
    if expiry_datetime is None:
        return expiry
    else:
        return min(expiry, expiry_datetime)


def encode_jwt_token(
    username: str,
    days_to_expiry: int,
    expiry_datetime: Optional[datetime],
    secret_key: str,
    jwt_username_field: str = "role",
    jwt_expiration_field: str = "exp",
) -> Tuple[str, datetime]:
    """Create a JWT token with the specified username and expiry"""
    jwt_token_expiry = _get_jwt_expiry(days_to_expiry, expiry_datetime)
    payload = {
        jwt_username_field: username,
        jwt_expiration_field: jwt_token_expiry.timestamp(),
    }
    jwt_token = jwt.encode(
        payload=payload,
        key=secret_key,
        algorithm="HS256",
    )
    return jwt_token, jwt_token_expiry


def decode_jwt_token(token: str, secret_key: str) -> Dict:
    """Decode the JWT token and return the payload"""
    return jwt.decode(token, secret_key, algorithms=["HS256"])


def verify_password(
    submitted_password: str,
    expected_hash: str,
    expiration: datetime,
    valid_from: Optional[datetime],
) -> Tuple[bool, str]:
    """Returns True if the password is correct"""
    if valid_from is not None:
        assert valid_from <= expiration
    now = datetime.now(tz=timezone.utc)
    if not bcrypt.checkpw(submitted_password.encode(), expected_hash.encode()):
        return False, "Credentials are incorrect"
    elif now > expiration:
        return False, "Credentials have expired"
    elif (valid_from is not None) and (now < valid_from):
        return False, "Credentials are not valid yet"
    else:
        return True, "Success"
