from pydantic import BaseModel

class TokenResponse(BaseModel):
    access_token: str
    access_token_type: str = "bearer"
    refresh_token: str
    refresh_token_type: str = "bearer"
