from fastapi import Depends, FastAPI, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from schemas import token_schema, user_schema
from utils import jwt_handler, password_hash
from dependencies import *
import uuid


router = APIRouter(prefix= '/auth', tags=["Auth"])

def register(
    db: Session,
    data: user_schema.UserCreate,
    role: str
) -> user_schema.UserPublic:
    username = data.username
    user_email = data.email
    if user_email in db.execute(select(model.User.email)).scalars():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email này đã được sử dụng!"
        )
    
    if username in db.execute(select(model.User.username)).scalars():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username này đã được sử dụng!"
        )
        
    newuser = model.User(
        id=str(uuid.uuid4()),
        email=data.email.strip().lower(),
        username=data.username,
        hashed_password=password_hash.hash_password(data.password),
        is_active=True,
        role=role
    )
    
    db.add(newuser)
    db.commit()
    db.refresh(newuser)
    
    return user_schema.UserPublic.model_validate(newuser)

@router.post('/register/user', response_model=user_schema.UserPublic)
def user_register(
    db: Annotated[Session, Depends(get_db)],
    data: user_schema.UserCreate
):
    return register(data=data, role='user', db=db)
    
@router.post('/register/admin', response_model=user_schema.UserPublic)
def admin_register(
    db: Annotated[Session, Depends(get_db)],
    data: user_schema.UserCreate
):
    return register(data=data, role='admin', db=db)
    
    
@router.post("/login", response_model=token_schema.TokenResponse)
def user_login(
    form: user_schema.UserLogin,
    db: Annotated[Session, Depends(get_db)]
):
    email = form.email.strip().lower()
    password = form.password
    
    user = db.execute(
        select(model.User).where(model.User.email == email)
    ).scalars().first()
    if not user or not password_hash.verify_password(password=password, hashed_password=user.hashed_password):
        raise credentials_error()
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tài khoản này đã bị vô hiệu hoá"
        )
        
    refresh_token=jwt_handler.create_refresh_token(user_email=email, db=db)
    access_token=jwt_handler.create_access_token(user_email=email, db=db)
    
        
    return token_schema.TokenResponse(
        refresh_token=refresh_token,
        access_token=access_token,
        token_type='bearer'
    )

@router.post('/token/refresh', response_model=token_schema.AccessTokenReponse)
def refresh_token(
    db: Annotated[Session, Depends(get_db)],
    data: token_schema.RefreshTokenRequest
):   
    db_token = jwt_handler.verify_refresh_token(token=data.refresh_token, db=db)
        
    new_access_token = jwt_handler.create_access_token(user_email=db_token.user_email, db=db)
    
    return token_schema.AccessTokenReponse(
        access_token=new_access_token,
        token_type='bearer'
    )

@router.post('/logout')
def logout(
    db: Annotated[Session, Depends(get_db)],
    data: token_schema.RefreshTokenRequest
):
    jwt_handler.revoke_refresh_token(token=data.refresh_token,db=db)
    
    