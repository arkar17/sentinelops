"""Request/response models for authentication routes. No hashes are ever serialized."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from sentinelops.identity.passwords import MAX_PASSWORD_LENGTH

PasswordField = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
TokenField = Field(min_length=16, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = PasswordField


class TokenPasswordRequest(BaseModel):
    token: str = TokenField
    password: str = PasswordField


class PasswordResetRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class ChangePasswordRequest(BaseModel):
    current_password: str = PasswordField
    new_password: str = PasswordField


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    status: str
    mfa_pending: str | None = None


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    current: bool


class RevokedCount(BaseModel):
    revoked: int
