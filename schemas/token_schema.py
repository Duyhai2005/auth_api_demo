from pydantic import BaseModel
from typing import Literal

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    
class AccessTokenReponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    
class RefreshTokenReponse(BaseModel):
    refresh_token: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"