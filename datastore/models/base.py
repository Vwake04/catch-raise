from pydantic import BaseModel
from typing import Optional, Union
from datetime import datetime, timezone
from beanie import Document, PydanticObjectId, Indexed

class BaseDocument(Document):
    """
    Base document model.
    """
    id: Optional[PydanticObjectId]
    created_at: Indexed(datetime) = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)

    class Config:
        orm_mode = True
    

class PaginationParams(BaseModel):
    limit: int = 10
    offset: int = 0
    substr: bool = True

