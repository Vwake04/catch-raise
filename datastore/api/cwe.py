"""
API definitions for blacklist.
"""

from fastapi import Depends
from fastapi_utils.cbv import cbv
from fastapi_utils.inferring_router import InferringRouter

from datastore.models.cve import Cve, CveRequestSchema
from datastore.models.cwe import Cwe, CweRequestSchema

from datastore.api.cve import CveResource

router = InferringRouter()


@cbv(router)
class CweResource:
    """
    All the views related to CWEs
    """

    model = Cwe
    order = [("cwe_id", -1)]
    cve_order = [("updated_at", -1), ("cve_id", -1)]

    @router.post("/cwe")
    async def list_cwes(
        self,
        req_params: CweRequestSchema = CweRequestSchema(),
    ):
        """
        List all the cwes.
        """
        try:
            query = self.model.find()

            # Filter the list of CWE
            if req_params.search:
                search = req_params.search.strip().lower()

                # By ID or by string
                search = search[4:] if search.startswith("cwe-") else search
                try:
                    search = int(search)
                    query = query.find(Cwe.cwe_id==f"CWE-{search}")
                except ValueError:
                    query = query.find({"name": {"$regex": search, "$options": "i"}})

            data = (
                await query.sort(self.order)
                .skip(req_params.offset)
                .limit(req_params.limit)
                .to_list()
            )
            
            return dict(
                data=data, success=True, message="Successfully Fetched CWEs."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch CWEs.")

    @router.post("/cwe/{cwe_id}")
    async def get_cwe(
        self,
        cwe_id: str
    ):
        """
        Get a specified CWE details
        """
        try:
            data = await self.model.find(Cwe.cwe_id == cwe_id.upper()).first_or_none()
            return dict(
                data=data, success=True, message="CWE Found."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch the CWE.")

    @router.post("/cwe/{cwe_id}/cve")
    async def get_cwe_cves(
        self,
        cwe_id: str,
        req_params: CveRequestSchema = CveRequestSchema()
    ):
        """
        Get all CVEs for the given CWE.
        """
        try:
            req_params.cwe = cwe_id
            req_params.substr = False
            data = await CveResource._list_cves(Cve, req_params, self.cve_order)
            return dict(
                data=data, success=True, message="CVEs Found."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch the CVEs.")