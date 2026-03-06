from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from models.database import Base

class UserAlert(Base):
    __tablename__ = "user_alerts"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False)
    industry = Column(String, nullable=True)    # e.g. "Healthcare"
    domain = Column(String, nullable=True)      # e.g. "mycompany.com"
    alert_on_industry = Column(Boolean, default=True)
    alert_on_domain = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
