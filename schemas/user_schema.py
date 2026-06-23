from pydantic import BaseModel, Field, field_validator, ConfigDict, EmailStr


class UserCreate(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=False,
        extra="forbid"
    )
    
    email: EmailStr
    username: str = Field(min_length=8, max_length=30)
    password: str = Field(min_length=10, max_length=100, 
                          description="Password phải có ít nhất 1 kí tự đặt biệt")
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not any(char.isalpha() for char in value):
            raise ValueError("Username phải chứa ít nhất một chữ cái")
        return value
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, value: str) -> str:
        if all(char.isalnum() for char in value):
            raise ValueError("Password phải chứ ít nhất một kí tự đặc biệt")
        return value
        

class UserLogin(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=False, 
        extra="forbid"
    )
    
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    id: str
    email: EmailStr
    username: str
    is_active: bool
    role: str
    

class UserInDB(UserPublic):
    hashed_password: str