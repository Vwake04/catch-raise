from datastore.checks import BaseCheck
from datastore.utilities.util import vendor_product_from_cpes, flatten_vendors_list


class FirstTime(BaseCheck):
    async def execute(self):
        old = flatten_vendors_list(vendor_product_from_cpes(self.cve_obj.raw_json["configurations"]))
        new = flatten_vendors_list(vendor_product_from_cpes(self.cve_json["configurations"]))
        payload = list(set(new) - set(old))
