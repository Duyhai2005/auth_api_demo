import jwt
import os
import uuid

from datetime import datetime, timedelta, timezone
from jwt import ExpiredSignatureError, InvalidTokenError
import dependencies
from dotenv import load_dotenv
from utils import password_hash
from schemas import token_schema
from models import model
from sqlalchemy.orm import Session
from sqlalchemy import select, update
from typing import Annotated
from fastapi import Depends
from database import Base, engine, get_db

load_dotenv()

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ISSUER = "auth-api-demo"
AUDIENCE = "auth-api-demo"
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_HOURS = 5

def create_token( 
    db: Session,
    user_email: str, token_type: str
) -> str:
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
    
    if token_type == 'refresh':
        new_token = model.Ref_token(
            token_hash=password_hash.hash_password(token),
            user_email=payload['sub'],
            jti=payload['jti'],
            revoke_at=None,
            expire_at=payload['exp']
        )
        
        db.add(new_token)
        db.commit()
        db.refresh(new_token)
    
    return token

def create_access_token(
    db: Annotated[Session, Depends(get_db)],
    user_email: str
) -> str:
    return create_token(user_email=user_email, token_type="access", db = db)

def create_refresh_token(
    user_email: str,
    db: Annotated[Session, Depends(get_db)]
) -> str:
    return create_token(user_email=user_email, token_type="refresh", db = db)

def decode_token(
    db: Session,
    token: str, type_token: str
) -> dict:
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
        user = db.execute(
            select(model.User).where(model.User.email == user_email)
        ).scalars().first()
        if not user:
            raise dependencies.credentials_error("Người dùng không tồn tại!")
    except InvalidTokenError:
        raise dependencies.credentials_error("Token không hợp lệ!")
    except ExpiredSignatureError:
        raise dependencies.credentials_error("Token đã hết hạn!")
    
    return payload

def decode_access_token(
    db: Annotated[Session, Depends(get_db)],
    token: str
) -> dict:
    return decode_token(token=token, type_token='access', db=db)

def decode_refresh_token(
    db: Annotated[Session, Depends(get_db)],
    token: str
) -> dict:
    return decode_token(token=token, type_token='refresh', db = db)

def verify_refresh_token(
    db: Annotated[Session, Depends(get_db)],
    token: str
):
    payload = decode_refresh_token(token=token, db=db)
    
    # db_token = fake_db.fake_token_db[payload['jti']]
    dbtoken = db.execute(
        select(model.Ref_token).where(model.Ref_token.jti == payload['jti'])
    ).scalars().first()
    
    if not password_hash.verify_password(token, dbtoken.token_hash):
        raise dependencies.credentials_error("Token không hợp lệ!")
    
    if dbtoken.revoke_at:
        raise dependencies.credentials_error("Token đã bị thu hổi!")

    
    return dbtoken
    
def revoke_refresh_token(db: Annotated[Session, Depends(get_db)], token: str):
    dbtoken = verify_refresh_token(token=token, db=db)
    jti = dbtoken.jti
    db.execute(
        update(model.Ref_token)
        .where(model.Ref_token.jti == jti)
        .values(revoke_at=datetime.now(timezone.utc))
    )
    db.commit()