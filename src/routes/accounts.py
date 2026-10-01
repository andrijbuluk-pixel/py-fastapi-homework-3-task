from collections import UserList
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.sql.functions import current_user

from config import get_jwt_auth_manager, get_settings, BaseAppSettings, settings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    UserRead,
    UserCreate,
    UserReadList,
    TokenActivate,
    Token
)
from fastapi.security import OAuth2PasswordBearer
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def create_user(db: AsyncSession, user: UserCreate):
    hashed = hash_password(user.password)

    user_stmt = select(UserGroupModel).where(UserGroupModel.name == "user")
    result_user = await db.execute(user_stmt)
    total_user = result_user.scalar_one_or_none()

    db_user = UserModel(
        email=user.email,
        _hashed_password=hashed,
        group_id=total_user.id,
    )

    create_activation_token = ActivationTokenModel(
        user=db_user,
    )

    db.add(db_user)
    db.add(create_activation_token)
    await db.commit()

    print(create_activation_token.token)

    await db.refresh(db_user)

    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.get("/all-user", response_model=list[UserReadList])
async def get_user_all(db: AsyncSession = Depends(get_db)):
    stmt = select(UserModel)
    result_user = await db.execute(stmt)
    db_user = result_user.scalars().all()

    return db_user



@router.post(
    "/register",
    response_model=UserRead,
    summary="Register a new user",
    description="<h2>This endpoint is intended for creating a new user.<h2>",
    responses={
        201: {
            "description": "<h3>User created successfully.</h3>",
        },
        400: {
            "description": "Invalid input.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid input data."}
                }
            },
        }
    },
    status_code=201
)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)

    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )

    try:
        return await create_user(db, user)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/login",
    response_model=Token,
    summary="Login a user",
    description=(
            "<h2>This endpoint is designed to log "
            "in to a user account and generate access "
            "and refresh tokens, after a successful login "
            "stores the refresh token in the database.</h2>"
    ),
    responses={
        201: {
            "description": "<h3>User has been successfully authorized.</h3>",
        },
        400: {
            "description": "Invalid input.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid input data."}
                }
            },
        }
    },
    status_code=201
)
async def user_login(
        email: str,
        password: str,

        db: AsyncSession = Depends(get_db),
        manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    try:
        db_user = await get_user_by_email(db, email)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )

    if not db_user or not verify_password(password, db_user._hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    user_active = db_user.is_active

    if not user_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated.",
        )

    access_token = manager.create_access_token(
        data={"sub": db_user.email},
    )
    refresh_token = manager.create_refresh_token(
        data={"sub": db_user.email}
    )

    db_refresh_token = RefreshTokenModel(
        token=refresh_token,
        user=db_user.id,
    )

    db.add(db_refresh_token)
    await db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post(
    "/activate",
    summary="Activate a user",
    description=(
            "<h2>This endpoint that allows users to "
            "activate their accounts by providing a valid "
            "activation token and email.</h2>"
    ),
    responses={
        200: {
            "description": "<h3>User account is already active.</h3>",
        }
    },
    status_code=200
)
async def activate_user(
        activate: TokenActivate,
        db: AsyncSession = Depends(get_db),
):
    user = select(UserModel).where(UserModel.email == activate.email)
    result = await db.execute(user)
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active.",
        )

    token = select(ActivationTokenModel).where(ActivationTokenModel.token == activate.token)
    result_token = await db.execute(token)
    db_token = result_token.scalar_one_or_none()

    if not db_token:
        raise HTTPException(
            status_code=404,
            detail="Activation token not found.",
        )

    if db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )


    if db_user.id != db_token.user_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid token",
        )

    db_user.is_active = True
    await db.delete(db_token)
    await db.commit()

    return {"message": "User account activated successfully."}
