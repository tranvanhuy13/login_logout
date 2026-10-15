from fastapi import APIRouter, Depends
from auth.dependencies import get_current_user
from .schemas import User
from .models import User as UserModel

router = APIRouter()

@router.get("/me", response_model=User)
def read_users_me(current_user: UserModel = Depends(get_current_user)):
    return current_user