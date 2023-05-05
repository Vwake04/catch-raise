from nested_lookup import nested_lookup

from beanie import WriteRules

from datastore.checks import BaseCheck
from datastore.init.cve_util import CveUtil
from datastore.models.vendors import Vendor
from datastore.models.products import Product
from datastore.utilities.util import vendor_product_from_cpes, flatten_vendors_list


class Cpes(BaseCheck):
    async def execute(self):
        old = nested_lookup("cpe23Uri", self.cve_obj.raw_json["configurations"])
        new = nested_lookup("cpe23Uri", self.cve_json["configurations"])

        payload = {
            "added": list(set(new) - set(old)),
            "removed": list(set(old) - set(new)),
        }

        # The CPEs list has been modified
        if payload["added"] or payload["removed"]:

            # Change the CVE's vendors attribute
            self.cve_obj.vendors = flatten_vendors_list(
                vendor_product_from_cpes(self.cve_json["configurations"])
            )
            await self.cve_obj.save()

            # Create the vendors and products objects if they don't exist
            vendors_products = vendor_product_from_cpes(payload["added"])

            for vendor, products in vendors_products.items():
                v_obj = await Vendor.find(Vendor.name==vendor).first_or_none()

                # Create the vendor and associate it to the CVE
                if not v_obj:
                    v_obj = await Vendor(name=vendor).save(link_rule=WriteRules.WRITE)

                # Do the same for its products
                for product in products:
                    p_obj = await Product.find(Product.name==product, Product.vendor_id==str(v_obj.id)).first_or_none()
                    if not p_obj:
                        p_obj = await Product(name=product, vendor_id=str(v_obj.id)).save()
                        v_obj.products.append(list(set([*v_obj.products, p_obj])))
                        await v_obj.save(link_rule=WriteRules.WRITE)
