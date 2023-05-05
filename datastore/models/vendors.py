from pymongo import (
    IndexModel, ASCENDING as PYMONGOASCENDING
)
from beanie import Link
from typing import List, Union
from datastore.models.products import Product
from datastore.utilities.util import _humanize_filter
from datastore.models.base import BaseDocument, PaginationParams

class Vendor(BaseDocument):
    """
    Model Class for CWEs
    """
    name: str
    products: List[Link[Product]] = []

    @property
    def human_name(self):
        return _humanize_filter(self.name)
        
    def __str__(self):
        return f"<Vendor {self.name}>"
    
    def __repr__(self):
        return f"<Vendor {self.name}>"


    class Settings:
        name = "vendors"
        indexes = [
            IndexModel(
                [("name", PYMONGOASCENDING)],
                name="name_index_asc",
                unique=True
            )
        ]
        

class VendorRequestSchema(PaginationParams):
    search: Union[str, None] = None