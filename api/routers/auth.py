# Import date & time utilities for JWT expiration handling
from datetime import timedelta, datetime, timezone

# Import typing helpers
from typing import Annotated, Optional

# FastAPI router and dependency tools
from fastapi import APIRouter, Depends, HTTPException

# OAuth2 form parser (username/password from form-data)
from fastapi.security import OAuth2PasswordRequestForm

# Pydantic base class for request/response models
from pydantic import BaseModel

# HTTP status codes
from starlette import status

# JWT encoding library
from jose import jwt

# Load environment variables from .env
from dotenv import load_dotenv

# OS module to read environment variables
import os

# Import database models
from api.models import User, Image

# Import database dependency + password helpers
# IMPORTANT: bcrypt_context is NOT imported here (by design)
from api.dependencies.deps import (
    db_dependency,
    hash_password,
    verify_password,
)

# Load variables from .env file into environment
load_dotenv()

# Create an API router for authentication endpoints
router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# Read JWT secret key from environment
SECRET_KEY = os.getenv("AUTH_SECRET_KEY")

# Read JWT algorithm (e.g., HS256)
ALGORITHM = os.getenv("AUTH_ALGORITHM")

# Fail fast if JWT config is missing
if not SECRET_KEY or not ALGORITHM:
    raise RuntimeError("AUTH_SECRET_KEY or AUTH_ALGORITHM not set")


# -------------------------------------------------
# Request / Response Schemas
# -------------------------------------------------

class UserCreateRequest(BaseModel):
    username: str
    password: str
    first_name: str
    last_name: str
    image: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str
    image: Optional[str] = None


# -------------------------------------------------
# Authentication Helper Functions
# -------------------------------------------------

def authenticate_user(username: str, password: str, db):
    """
    Authenticate user credentials.
    """

    # Fetch user by username
    user = db.query(User).filter(User.username == username).first()

    # User not found
    if not user:
        return False

    # Verify password using safe helper
    if not verify_password(password, user.hashed_password):
        return False

    # Fetch user's image (optional)
    image = db.query(Image).filter(Image.user_id == user.id).first()
    user.image = image.image if image else None

    return user


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    """
    Create a signed JWT access token.
    """
    payload = {
        "sub": username,
        "id": user_id,
        "exp": datetime.now(timezone.utc) + expires_delta,
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


# -------------------------------------------------
# API Routes
# -------------------------------------------------

@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(
    db: db_dependency,
    create_user_request: UserCreateRequest,
):
    """
    Register a new user.
    """

    # Create User ORM object
    user = User(
        username=create_user_request.username,
        first_name=create_user_request.first_name,
        last_name=create_user_request.last_name,
        hashed_password=hash_password(create_user_request.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    # Create image record if provided
    image = Image(
        image=create_user_request.image,
        user_id=user.id,
    )

    db.add(image)
    db.commit()

    return {"message": "User created successfully"}


@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency,
):
    """
    Login endpoint that returns a JWT token.
    """

    user = authenticate_user(form_data.username, form_data.password, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate user.",
        )

    token = create_access_token(
        user.username,
        user.id,
        timedelta(minutes=20),
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "image": user.image,
    }
