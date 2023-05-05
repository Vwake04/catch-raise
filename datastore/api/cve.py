"""
API definitions for blacklist.
"""

from fastapi import Depends
from fastapi_utils.cbv import cbv
from beanie import PydanticObjectId
from fastapi_utils.inferring_router import InferringRouter

from datastore.constants import PRODUCT_SEPARATOR
from datastore.models.vendors import Vendor
from datastore.models.products import Product
from datastore.models.cve import Cve, CveRequestSchema


router = InferringRouter()


@cbv(router)
class CveResource:
    """
    All the views related to CVEs
    """

    model = Cve
    order = [("updated_at", -1), ("cve_id", -1)]

    @staticmethod
    async def _list_cves(model: Cve, req_params: CveRequestSchema, order):
        """
        List all the cves based on the req parameters
        """
        query = model.find()

        vendor_req = req_params.vendor
        product_req = req_params.product

        if vendor_req:
            vendor_req = vendor_req.replace(" ", "").lower()
        if product_req:
            product_req = product_req.replace(" ", "").lower()

        # Filter by keyword
        if req_params.search:
            possible_vendor = req_params.search.replace(" ", "").lower()
            possible_product = req_params.search.replace(" ", "_").lower()

            vendor = await Vendor.find(
                Vendor.name == possible_vendor
            ).first_or_none()

            if vendor:
                product = await Product.find(
                    Product.name == possible_product,
                    Product.vendor_id == str(vendor.id)
                ).first_or_none()
            else:
                product = await Product.find(Product.name==possible_product).first_or_none()

            # filter for cve_id and summary
            cve_search_query = [
                {"cve_id": {"$regex": req_params.search, "$options": "i"}},
                {"summary": {"$regex": req_params.search, "$options": "i"}},
            ]

            # include cves with vendor
            if vendor:
                cve_search_query.append(
                    {"vendors": {"$regex": vendor.name, "$options": "i"}}
                )
            # include cves with product
            if product:
                cve_search_query.append(
                    {"vendors": {"$regex": product.name, "$options": "i"}}
                )

            query = query.find({"$or": cve_search_query})

        # Filter by CWE
        if req_params.cwe:
            if req_params.substr:
                query = query.find({"cwes": {"$regex": req_params.cwe, "$options": "i"}})
            else:
                query = query.find({"cwes": req_params.cwe})

        # Filter by CVSS score
        severity = ["none", "low", "medium", "high", "critical"]
        if req_params.cvss and req_params.cvss.lower() in severity:
            if req_params.cvss.lower() == "none":
                query = query.find(Cve.cvss3 == None)

            if req_params.cvss.lower() == "low":
                query = query.find({"$and": [{"cvss3": {"$gte": 0.1}}, {"cvss3": {"$lte": 3.9}}]})

            if req_params.cvss.lower() == "medium":
                query = query.find({"$and": [{"cvss3": {"$gte": 4.0}}, {"cvss3": {"$lte": 6.9}}]})

            if req_params.cvss.lower() == "high":
                query = query.find({"$and": [{"cvss3": {"$gte": 7.0}}, {"cvss3": {"$lte": 8.9}}]})

            if req_params.cvss.lower() == "critical":
                query = query.find({"$and": [{"cvss3": {"$gte": 9.0}}, {"cvss3": {"$lte": 10.0}}]})

        # Filter by vendor and product
        if vendor_req and product_req:
            vendor = await Vendor.find(Vendor.name==vendor_req).first_or_none()
            if not vendor:
                raise Exception("Vendor not found.")

            product = await Product.find(
                Product.name == product_req,
                Product.vendor_id == str(vendor.id)
            ).first_or_none()
            if not product:
                raise Exception("Product not found.")

            query = query.find(
                {"vendors": {
                    "$regex": f"{vendor.name}::{product.name}", 
                    "$options": "i"
                }}
            )

        # Filter by vendor
        elif vendor_req:
            vendor = await Vendor.find(Vendor.name==vendor_req).first_or_none()
            if not vendor:
                raise Exception("Vendor not found.")
            query = query.find({"vendors": {"$regex": f"{vendor.name}", "$options": "i"}})

        # Filter by product only
        elif product_req:
            product = await Product.find(Product.name==product_req).first_or_none()
            if not product:
                raise Exception("Product not found.")
            query = query.find({"vendors": {"$regex": f"{product.name}", "$options": "i"}})

        data = await query.sort(order).skip(req_params.offset).limit(req_params.limit).to_list()
        return data
        
    @router.post("/cve")
    async def list_cves(
        self,
        req_params: CveRequestSchema = CveRequestSchema(),
    ):
        """
        List all the cves.
        """
        try:
            data = await CveResource._list_cves(self.model, req_params, self.order)
            return dict(
                data=data, success=True, message="Successfully Fetched CVEs."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error=str(e))


    @router.post("/cve/{cve_id}")
    async def get_cve(
        self,
        cve_id: str
    ):
        """
        Get a specified CVE details
        """
        try:
            data = await self.model.find(Cve.cve_id == cve_id).first_or_none()
            return dict(
                data=data, success=True, message="CVE Found."
            )
        except Exception as e:
            return dict(data={}, success=False, error=str(e))