from pydantic import BaseModel
from typing import Literal
from datetime import datetime

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    
class AccessTokenReponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    
class RefreshTokenReponse(BaseModel):
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"

class RefreshTokenRequest(BaseModel):
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    
    
class RefreshTokenInDB(BaseModel):
    user_email: str
    token_hash: str
    jti: str
    expires_at: datetime
    revoked_at: datetime | None