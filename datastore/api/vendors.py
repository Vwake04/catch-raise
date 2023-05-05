"""
API definitions for blacklist.
"""

from fastapi import Depends
from fastapi_utils.cbv import cbv
from fastapi_utils.inferring_router import InferringRouter

from datastore.models.cve import Cve, CveRequestSchema
from datastore.models.vendors import Vendor, VendorRequestSchema

from datastore.api.cve import CveResource

router = InferringRouter()


@cbv(router)
class VendorResource:
    """
    All the views related to Vendor
    """

    model = Vendor
    order = [("name", 1)]
    cve_order = [("updated_at", -1), ("cve_id", -1)]

    @router.post("/vendors")
    async def list_vendors(
        self,
        req_params: VendorRequestSchema,
    ):
        """
        List all the Vendors.
        """
        try:
            query = self.model.find(fetch_links=True)

            # Search by keyword
            if req_params.search:
                search = (
                    req_params.search
                    .strip().lower()
                    .replace("%", "")
                    .replace("_", "")
                    .replace(" ", "_")
                )
                query = query.find({"name": {"$regex": search, "$options": "i"}}, fetch_links=True)

            data = (
                await query.sort(self.order)
                .skip(req_params.offset)
                .limit(req_params.limit)
                .to_list()
            )
            
            return dict(
                data=data, success=True, message="Successfully Fetched Vendors."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch Vendors.")

    @router.post("/vendors/{vendor}")
    async def get_vendor(
        self,
        vendor: str
    ):
        """
        Get a specified vendor details
        """
        try:
            data = await self.model.find(Vendor.name == vendor.lower(), fetch_links=True).first_or_none()
            return dict(
                data=data, success=True, message="Vendor Found."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch the Vendor.")

    @router.post("/vendors/{vendor}/cve")
    async def get_vendor_cves(
        self,
        vendor: str,
        req_params: CveRequestSchema = CveRequestSchema()
    ):
        """
        Get a Vendor related CVEs
        """
        try:
            req_params.vendor = vendor
            data = await CveResource._list_cves(Cve, req_params, self.cve_order)
            return dict(
                data=data, success=True, message="CVEs Found."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch the CWE.")