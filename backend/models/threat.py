from sqlalchemy import Column, Integer, String, DateTime, Float, Text
from sqlalchemy.sql import func
from models.database import Base

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id = Column(Integer, primary_key=True, index=True)
    indicator_type = Column(String, index=True)
    indicator_value = Column(String, index=True)
    threat_type = Column(String, index=True)
    confidence_score = Column(Float, default=0.0)
    source = Column(String)
    country = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    tags = Column(String, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
