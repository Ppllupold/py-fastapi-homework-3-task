from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.dependencies import get_jwt_auth_manager, get_settings
from src.config.settings import BaseAppSettings
from src.database import get_db, UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel, RefreshTokenModel, \
    PasswordResetTokenModel
from src.exceptions import TokenExpiredError, InvalidTokenError
from src.schemas.accounts import UserRead, UserCredentialsSchema, UserActivationSchema, UserResetPasswordSchema, \
    UserBase, UserLoginResponseSchema, AccessTokenRefreshSchema
from src.security.token_manager import JWTAuthManagerInterface

router = APIRouter()

SUCCESS_MSG = "If you are registered, you will receive an email with instructions."


@router.post("/register/", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserCredentialsSchema, db: AsyncSession = Depends(get_db)):
    exists = await db.scalar(select(UserModel.id).where(UserModel.email == user_data.email.lower()))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        if group is None:
            raise HTTPException(status_code=500, detail="An error occurred during user creation.")

        user = UserModel.create(
            email=user_data.email.lower(),
            raw_password=user_data.password,
            group_id=group.id,
        )
        db.add(user)
        await db.flush()  # user.id

        db.add(ActivationTokenModel(user_id=user.id))

        await db.commit()
        await db.refresh(user)

        return UserRead(id=user.id, email=user.email)

    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user_account(user_data: UserActivationSchema, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email.lower()))
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token = await db.scalar(select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
    if token is None or token.token != user_data.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset_request(user_data: UserBase, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email.lower()))

    if user is not None and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        db.add(PasswordResetTokenModel(user_id=user.id))
        await db.commit()

    return {"message": SUCCESS_MSG}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def password_reset_complete(user_data: UserResetPasswordSchema, db: AsyncSession = Depends(get_db)):
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email.lower()))
        if user is None or not user.is_active:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        token = await db.scalar(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        if token is None:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        now = datetime.now(timezone.utc)
        expires_at = token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if token.token != user_data.token or expires_at < now:
            await db.delete(token)
            await db.commit()  # тести перевіряють, що токен видалено
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = user_data.password
        await db.delete(token)

        await db.commit()
        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login(
        user_data: UserLoginResponseSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email.lower()))
    if user is None or not user.verify_password(user_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    payload = {"user_id": user.id}
    access_token = jwt_manager.create_access_token(payload)
    refresh_token = jwt_manager.create_refresh_token(payload)

    try:
        db.add(RefreshTokenModel.create(user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(body: AccessTokenRefreshSchema, db: AsyncSession = Depends(get_db),
                               jwt_manager=Depends(get_jwt_auth_manager)):
    try:
        payload = jwt_manager.decode_refresh_token(body.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    token_row = await db.scalar(select(RefreshTokenModel).where(RefreshTokenModel.token == body.refresh_token))
    if token_row is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": new_access}
