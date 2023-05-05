"""
API definitions for blacklist.
"""

from fastapi import Depends
from fastapi_utils.cbv import cbv
from fastapi_utils.inferring_router import InferringRouter

from datastore.models.vendors import Vendor
from datastore.models.cve import Cve, CveRequestSchema
from datastore.models.products import Product, ProductRequestSchema

from datastore.api.cve import CveResource

router = InferringRouter()


@cbv(router)
class ProductResource:
    """
    All the views related to Product
    """

    model = Product
    order = [("name", 1)]
    cve_order = [("updated_at", -1), ("cve_id", -1)]

    @router.post("/products")
    async def get_products(self, req_params: ProductRequestSchema = ProductRequestSchema()):
        """
        Get all the products.
        """
        try:
            query = self.model.find()
            data = (
                await query.sort(self.order)
                .skip(req_params.offset)
                .limit(req_params.limit)
                .to_list()
            )

            return dict(
                data=data, success=True, message="Successfully Fetched Products."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch Products.")

    @router.post("/vendors/{vendor}/products")
    async def list_vendor_products(
        self,
        vendor: str,
        req_params: ProductRequestSchema,
    ):
        """
        List all the Products of a Vendor.
        """
        try:
            query = self.model.find()
            if vendor:
                vendor_t = await Vendor.find(Vendor.name == vendor, fetch_links=True).first_or_none()
                if vendor_t:
                    query = query.find(Product.vendor_id == str(vendor_t.id))

            # Search by keyword
            if req_params.search:
                search = (
                    req_params.search
                    .strip().lower()
                    .replace("%", "")
                    .replace("_", "")
                    .replace(" ", "_")
                )
                query = query.find({"name": {"$regex": search, "$options": "i"}})

            data = (
                await query.sort(self.order)
                .skip(req_params.offset)
                .limit(req_params.limit)
                .to_list()
            )
            return dict(
                data=data, success=True, message="Successfully Fetched Products of Vendor."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch Products of Vendor.")

    @router.post("/vendors/{vendor}/products/{product}")
    async def get_vendor_product(
        self,
        vendor: str,
        product: str,
    ):
        """
        Get Product of a Vendor.
        """
        try:
            vendor_t = await Vendor.find(Vendor.name == vendor, fetch_links=True).first_or_none()
            if vendor_t:
                product_t = await self.model.find(
                    Product.name == product,
                    Product.vendor_id == str(vendor_t.id)
                ).first_or_none()
                if not product_t:
                    Exception("Not Found.")
            else:
                raise Exception("Not Found.")

            return dict(
                data=product_t, success=True, message="Successfully Fetched Product of a Vendor."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch Product of a Vendor.")

    @router.post("/vendors/{vendor}/products/{product}/cve")
    async def get_vendor_product_cve(
        self,
        vendor: str,
        product: str,
        req_params: CveRequestSchema = CveRequestSchema()
    ):
        """
        Get Product of a Vendor.
        """
        try:
            req_params.vendor = vendor
            req_params.product = product
            data = await CveResource._list_cves(Cve, req_params, self.cve_order)

            return dict(
                data=data, success=True, message="Successfully Fetched Product of a Vendor."
            )
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            return dict(data={}, success=False, error="Failed to fetch Product of a Vendor.")
