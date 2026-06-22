import jwt
import os
import uuid

from datetime import datetime, timedelta, timezone
from jwt.exceptions import InvalidTokenError

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ISSUER = "auth-api-demo"
AUDIENCE = "auth-api-demo"
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_HOURS = 5

def create_token(user_email: str, token_type: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_email,
        "type": token_type,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES) 
                    if token_type is "access"
                    else timedelta(hours=REFRESH_TOKEN_HOURS),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "jti": str(uuid.uuid4())
    }
    token = jwt.encode(payload=payload, key = SECRET_KEY, algorithm=ALGORITHM)
    return token

def create_access_token(user_email: str) -> str:
    return create_token(user_email, "access")

def create_refresh_token(user_email: str) -> str:
    return create_token(user_email, "refresh")

# def decode_token(token: str, type_token: str) -> dict:
    