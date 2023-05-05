from pymongo import (
    IndexModel, ASCENDING as PYMONGOASCENDING
)

from typing import Union
from datastore.models.base import BaseDocument, PaginationParams


class Product(BaseDocument):
    """
    Model Class for Product
    """
    name: str
    vendor_id: str

    def __hash__(self):
        return hash(f"{self.name}:{self.vendor_id}")

    def __eq__(self, obj):
        return self.name == obj.name and self.vendor_id == obj.vendor_id

    def __str__(self):
        return f"<Product {self.name}>"
    
    def __repr__(self):
        return f"<Product {self.name}>"

    class Settings:
        name = "products"
        indexes = [
            IndexModel(
                [
                    ("name", PYMONGOASCENDING), 
                    ("vendor_id", PYMONGOASCENDING), 
                ],
                name="name_vendor_id_index_asc",
                unique=True
            )
        ]


class ProductRequestSchema(PaginationParams):
    search: Union[str, None] = None