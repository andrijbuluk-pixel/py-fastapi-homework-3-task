from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserRead(UserBase):
    id: int

    model_config = {
        "from_attributes": True
    }


class UserReadList(UserBase):
    id: int
    is_active: bool

    model_config = {
        "from_attributes": True
    }


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenActivate(UserBase):
    token: str


