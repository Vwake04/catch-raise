from pymongo import (
    IndexModel, ASCENDING as PYMONGOASCENDING
)
from typing import Union

from datastore.models.base import BaseDocument, PaginationParams


class Cwe(BaseDocument):
    """
    Model Class for CWEs
    """
    cwe_id: str
    name: str | None = None
    description: str | None = None

    @property
    def short_id(self):
        if not self.cwe_id.startswith("CWE-"):
            return None
        return self.cwe_id.split("CWE-")[1]

    def __str__(self):
        return f"<Cwe {self.cwe_id}>"
    
    def __repr__(self):
        return f"<Cwe {self.cwe_id}>"

    class Settings:
        name = "cwes"
        indexes = [
            IndexModel(
                [("cwe_id", PYMONGOASCENDING)],
                name="cwe_id_index_asc",
                unique=True
            )
        ]
        

class CweRequestSchema(PaginationParams):
    search: Union[str, None] = None