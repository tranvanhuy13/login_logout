from pydantic import BaseModel

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    email: str
    password: str

class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True

class OTPVerify(BaseModel):
    email: str
    otp: str

class OTPResend(BaseModel):
    email: str