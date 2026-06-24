from fastapi import Depends, FastAPI, APIRouter, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from schemas import token_schema, user_schema
from utils import jwt_handler, password_hash
from dependencies import *

router = APIRouter(prefix='/users', tags=['users'])

@router.get('/me', response_model=model.User)
def get_me(
    db: Annotated[Session, Depends(get_db)],
    user_email: str = Depends(get_current_user)
):
    return db.execute(select(model.User).where(model.User.email == user_email)).scalars().first()

@router.get('/all')
def get_all_user(
    db: Annotated[Session, Depends(get_db)],
    user_email: str = Depends(get_current_user)
) -> list[model.User]:
    if db.execute(select(model.User).where(model.User.email == user_email)).scalars().first().role != 'admin':
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bạn không có quyền thực hiện hành động này!"
        )
    
    return db.execute(select(model.User))