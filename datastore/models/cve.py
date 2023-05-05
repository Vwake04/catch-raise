import json
from pymongo import (
    IndexModel, ASCENDING as PYMONGOASCENDING
)
from typing import Union, Optional
from beanie import Indexed
from pydantic import validator
from datetime import datetime, timezone

from datastore.models.base import BaseDocument, PaginationParams

class Cve(BaseDocument):
    """
    Model Class for CWEs
    """
    # CVE are sorted by last modified date, we need to index it.
    updated_at: Indexed(datetime) = datetime.now(timezone.utc)

    cve_id: str
    # will contain the raw data
    raw_json: dict = {}

    summary: str
    cwes: list | None = []
    vendors: list | None = []
    cvss2: float | None = None
    cvss3: float | None = None

    @validator("vendors", "cwes", pre=True)
    def obj_to_str(cls, v):
        if v is None:
            return []
        return v

    def __str__(self):
        return f"<Cve {self.cve_id}>"
    
    def __repr__(self):
        return f"<Cve {self.cve_id}>"
        
    @property
    def cvss_weight(self):
        """Only used to sort several CVE by their CVSS"""
        w = 0
        if self.cvss2:
            w += self.cvss2
        if self.cvss3:
            w += self.cvss3
        return w

    class Settings:
        name = "cves"
        indexes = [
            IndexModel(
                [("cve_id", PYMONGOASCENDING)],
                name="cve_id_index_asc"
            ),
            IndexModel(
                [("summary", PYMONGOASCENDING)],
                name="summary_index_asc"
            ),
            IndexModel(
                [("cwes", PYMONGOASCENDING)],
                name="cwes_index_asc"
            ),
        ]


class CveRequestSchema(PaginationParams):
    search: Union[str, None] = None
    vendor: Union[str, None] = None
    product: Union[str, None] = None
    cvss: Union[str, None] = None
    cwe: Union[str, None] = None
    tag: Union[str, None] = None
    user_id: Union[str, None] = None