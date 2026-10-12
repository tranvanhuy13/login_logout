from dataclasses import dataclass

@dataclass
class User:
    id: int
    username: str
    email: str
    hashed_password: str
    is_active: bool = False
    otp: str | None = None
    otp_expires_at: str | None = None