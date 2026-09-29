from collections import UserList
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
    db.add(db_user)
    await db.commit()
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
