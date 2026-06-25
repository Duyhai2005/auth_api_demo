from fastapi import Depends, FastAPI, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from schemas import token_schema, user_schema
from utils import jwt_handler, password_hash
from dependencies import *

router = APIRouter(prefix='/users', tags=['users'])

@router.get('/me', response_model=user_schema.UserPublic)
def get_me(
    db: Annotated[Session, Depends(get_db)],
    user_email: str = Depends(get_current_user)
):
    user = db.execute(select(model.User).where(model.User.email == user_email)).scalars().first()
    return user_schema.UserPublic.model_validate(user)

@router.get('/all', response_model=list[user_schema.UserPublic])
def get_all_user(
    db: Annotated[Session, Depends(get_db)],
    user_email: str = Depends(get_current_user)
):
    if db.execute(select(model.User).where(model.User.email == user_email)).scalars().first().role != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bạn không có quyền thực hiện hành động này!"
        )
    
    return db.execute(select(model.User)).scalars().all()