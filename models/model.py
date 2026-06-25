from __future__ import annotations

from datetime import UTC, datetime
from sqlalchemy import DateTime, String, Boolean
from sqlalchemy.orm import Mapped, mapped_column

from database import Base

class User(Base):
    __tablename__ = "users"
    
    id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    username: Mapped[str] = mapped_column(String(40), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(120), primary_key=True, index=True)
    is_active: Mapped[Boolean] = mapped_column(Boolean)
    role: Mapped[str] = mapped_column(String(10))
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    
class Ref_token(Base):
    __tablename__ = "ref_tokens"
    
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    user_email: Mapped[str] = mapped_column(String(120), nullable=False)
    jti: Mapped[str] = mapped_column(String(36), primary_key=True, nullable=False, unique=True)
    revoke_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    expire_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
