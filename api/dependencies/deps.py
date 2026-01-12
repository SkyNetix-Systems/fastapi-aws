# -------------------------------------------------
# Imports
# -------------------------------------------------

from typing import Annotated
import os

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from api.models import SessionLocal


# -------------------------------------------------
# Environment Variables
# -------------------------------------------------

load_dotenv()

SECRET_KEY = os.getenv("AUTH_SECRET_KEY")
ALGORITHM = os.getenv("AUTH_ALGORITHM")

if not SECRET_KEY or not ALGORITHM:
    raise RuntimeError("AUTH_SECRET_KEY or AUTH_ALGORITHM not set")


# -------------------------------------------------
# Database Dependency
# -------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]


# -------------------------------------------------
# Password Hashing (ARGON2 ✅ FINAL FIX)
# -------------------------------------------------

"""
ARGON2:
- No length limits
- No C-extension dependency
- No Windows bugs
- Recommended by OWASP
"""

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto"
)

def hash_password(password: str) -> str:
    """
    Hash password using Argon2.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify password using Argon2.
    """
    return pwd_context.verify(plain_password, hashed_password)


# -------------------------------------------------
# OAuth2 / JWT Configuration
# -------------------------------------------------

oauth2_bearer = OAuth2PasswordBearer(tokenUrl="auth/token")

oauth2_bearer_dependency = Annotated[
    str,
    Depends(oauth2_bearer)
]


# -------------------------------------------------
# Current User Dependency
# -------------------------------------------------

async def get_current_user(token: oauth2_bearer_dependency):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")
        user_id = payload.get("id")

        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate user."
            )

        return {
            "username": username,
            "id": user_id
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate user."
        )


user_dependency = Annotated[
    dict,
    Depends(get_current_user)
]
