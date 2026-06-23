from fastapi import HTTPException, status, Depends
from utils import jwt_handler
import fake_db
from fastapi.security import  OAuth2PasswordBearer

def credentials_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Không thể xác thực thông tin đăng nhập",
        headers={'WWW-Authenticate' : 'Bearer'}
    )
    
def get_current_user(token: str = Depends(OAuth2PasswordBearer(tokenUrl="auth/login"))) -> str:
    user_email = jwt_handler.decode_access_token(token=token)
    
    user = fake_db.fake_users_db.get(user_email)
    if user is None or user.is_active == False:
        raise credentials_error()
    else:
        return user.email
    
