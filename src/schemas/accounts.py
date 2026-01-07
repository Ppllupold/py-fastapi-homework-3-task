from pydantic import BaseModel, EmailStr, field_validator

from src.database.validators.accounts import validate_password_strength, validate_email


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email", mode="before")
    @classmethod
    def validate_email(cls, value):
        return validate_email(value)


class UserCredentialsSchema(UserBase):
    password: str

    @field_validator("password", mode="before")
    @classmethod
    def validate_password(cls, v):
        return validate_password_strength(v)


class UserRead(UserBase):
    id: int


class UserActivationSchema(UserBase):
    token: str


class UserResetPasswordSchema(UserCredentialsSchema):
    token: str


class UserLoginResponseSchema(UserBase):
    password: str


class AccessTokenRefreshSchema(BaseModel):
    refresh_token: str
