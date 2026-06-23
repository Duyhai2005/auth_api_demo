import jwt
import os
import uuid

from datetime import datetime, timedelta, timezone
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from fastapi import HTTPException, status
import dependencies
from dotenv import load_dotenv
from utils import password_hash
import fake_db
from schemas import token_schema, user_schema

load_dotenv()

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
                    if token_type == "access"
                    else now + timedelta(hours=REFRESH_TOKEN_HOURS),
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

def decode_token(token: str, type_token: str) -> dict:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require" :["sub", "type", "iss", "aud", "iat", "exp", "jti"]}
        )
        if payload.get('type') != type_token:
            raise dependencies.credentials_error(f"Token không phải {type_token} token!")
        user_email = payload.get('sub')
        if user_email not in fake_db.fake_users_db:
            raise dependencies.credentials_error("Người dùng không tồn tại!")
    except InvalidTokenError:
        raise dependencies.credentials_error("Token không hợp lệ!")
    except ExpiredSignatureError:
        raise dependencies.credentials_error("Token đã hết hạn!")
    
    return payload

def decode_access_token(token: str) -> dict:
    return decode_token(token=token, type_token='access')

def decode_refresh_token(token: str) -> dict:
    return decode_token(token=token, type_token='refresh')

def verify_refresh_token(token: str) -> token_schema.RefreshTokenInDB:
    payload = decode_refresh_token(token)
    
    db_token = fake_db.fake_token_db[payload['jti']]
    
    if not password_hash.verify_password(token, db_token.token_hash):
        raise dependencies.credentials_error("Token không hợp lệ!")
    
    if db_token.revoked_at:
        raise dependencies.credentials_error("Token đã bị thu hổi!")

    
    return db_token
    
def revoke_refresh_token(token: str):
    db_token = verify_refresh_token(token)
    db_token.revoked_at = datetime.now(timezone.utc)
    