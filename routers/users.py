from fastapi import Depends, FastAPI, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from schemas import token_schema, user_schema
from utils import jwt_handler, password_hash
from fake_db import *
from dependencies import *

router = APIRouter(prefix='/users', tags=['users'])

@router.get('/me', response_model=user_schema.UserPublic)
def get_me(
    user_email: str = Depends(get_current_user)
):
    return fake_users_db.get(user_email)

@router.get('/all')
def get_all_user(
    user_email: str = Depends(get_current_user)
) -> list[user_schema.UserPublic]:
    if fake_users_db.get(user_email).role != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bạn không có quyền thực hiện hành động này!"
        )
    
    return fake_users_db.values()