from fastapi import HTTPException, status, Depends
from utils import jwt_handler
from fastapi.security import  OAuth2PasswordBearer
from typing import Annotated
from sqlalchemy import select
from sqlalchemy.orm import Session
from database import get_db
from models import model

def credentials_error(message: str = "Không thể xác thực thông tin đăng nhập") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=message,
        headers={'WWW-Authenticate' : 'Bearer'}
    )
    
def get_current_user(
    db: Annotated[Session, Depends(get_db)],
    token: str = Depends(OAuth2PasswordBearer(tokenUrl="auth/login"))
) -> str:
    payload = jwt_handler.decode_access_token(token=token)
    user_email = payload['sub']
    result_user = db.execute(
        select(model.User).where(model.User.email == user_email)
    )
    existing_user = result_user.scalars().first()
    if not existing_user or existing_user.is_active == False:
        raise credentials_error()
    else:
        return existing_user.email
    
