from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.sql import func

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String(50),
        nullable=False
    )

    email = Column(
        String(100),
        unique=True,
        nullable=False,
        index=True
    )

    password = Column(
        String(255),
        nullable=False
    )

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    input_type = Column(String(20), nullable=False)  # url | email | apk | payment | qr
    target = Column(String(500), nullable=False)      # what was scanned (url, filename, upi id...)

    risk = Column(String(20), nullable=False)
    score = Column(Integer, nullable=False)
    reasons = Column(Text, nullable=True)  # JSON-encoded list of reason strings

    created_at = Column(DateTime(timezone=True), server_default=func.now())
