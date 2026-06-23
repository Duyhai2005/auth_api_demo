from fastapi import Depends, FastAPI, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from schemas import token_schema, user_schema
from utils import jwt_handler, password_hash
from fake_db import *
from dependencies import *
import uuid

router = APIRouter(prefix= '/auth', tags=["Auth"])

def register(
    data: user_schema.UserCreate,
    role: str
) -> user_schema.UserPublic:
    username = data.username
    user_email = data.email
    if user_email in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email này đã được sử dụng!"
        )
    if username in [user.username for user in fake_users_db.values()]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username này đã được sử dụng!"
        )
        
    newuser = user_schema.UserInDB(
        id=str(uuid.uuid4()),
        email=data.email.strip().lower(),
        username=data.username,
        hashed_password=password_hash.hash_password(data.password),
        is_active=True,
        role=role
    )
    fake_users_db[user_email] =  newuser
    
    return user_schema.UserPublic(
        id=newuser.id,
        email=newuser.email,
        username=newuser.username,
        is_active=newuser.is_active,
        role=newuser.role
    )

@router.post('/register/user', response_model=user_schema.UserPublic)
def user_register(
    data: user_schema.UserCreate
):
    return register(data=data, role='user')
    
@router.post('/register/admin', response_model=user_schema.UserPublic)
def admin_register(
    data: user_schema.UserCreate
):
    return register(data=data, role='admin')
    
    
@router.post("/login", response_model=token_schema.TokenResponse)
def user_login(
    form: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    email = form.username.strip().lower()
    password = form.password
    
    user = fake_users_db.get(email)
    if not user or not password_hash.verify_password(password=password, hashed_password=user.hashed_password):
        raise credentials_error()
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tài khoản này đã bị vô hiệu hoá"
        )
        
    return token_schema.TokenResponse(
        refresh_token=jwt_handler.create_refresh_token(email),
        access_token=jwt_handler.create_access_token(email),
        token_type='bearer'
    )

@router.post('/token/refresh', response_model=token_schema.AccessTokenReponse)
def refresh_token(
    data: token_schema.RefreshTokenRequest
):
    payload = jwt_handler.decode_refresh_token(data.refresh_token)    
    user_email = payload['sub']
    user = fake_users_db.get(user_email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Người dùng không tồn tại"
        )
        
    new_access_token = jwt_handler.create_access_token(user_email=user_email)
    
    return token_schema.AccessTokenReponse(
        access_token=new_access_token,
        token_type='bearer'
    )

@router.post('/logout')
def logout(
    token: str = Depends(OAuth2PasswordBearer(tokenUrl="auth/login"))
):
    pass