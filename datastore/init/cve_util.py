import arrow
from nested_lookup import nested_lookup

from beanie import WriteRules

from datastore.init.utils import info
from datastore.models.cve import Cve
from datastore.models.cwe import Cwe
from datastore.models.products import Product
from datastore.models.vendors import Vendor
from datastore.utilities.util import vendor_product_from_cpes, flatten_vendors_list, get_cwes_list


class CveUtil(object):
    @classmethod
    def cve_has_changed(cls, cve_db, cve_json):
        return arrow.get(cve_json["lastModifiedDate"]) != cve_db.updated_at

    @classmethod
    async def create_cve(cls, cve_json):
        cvss2 = (
            cve_json["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            if "baseMetricV2" in cve_json["impact"]
            else None
        )
        cvss3 = (
            cve_json["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            if "baseMetricV3" in cve_json["impact"]
            else None
        )

        # Construct CWE and CPE lists
        cwes = get_cwes_list(
            cve_json["cve"]["problemtype"]["problemtype_data"][0]["description"]
        )
        cpes = vendor_product_from_cpes(cve_json["configurations"])
        vendors = flatten_vendors_list(cpes)

        # Create the CVE
        cve = await Cve(
            cve_id=cve_json["cve"]["CVE_data_meta"]["ID"],
            summary=cve_json["cve"]["description"]["description_data"][0]["value"],
            raw_json=cve_json,
            vendors=vendors,
            cwes=cwes,
            cvss2=cvss2,
            cvss3=cvss3,
            created_at=arrow.get(cve_json["publishedDate"]).datetime,
            updated_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
        ).save()

        # Add the CWE that not exists yet in database
        for cwe in cwes:
            cwe_obj = await Cwe.find(Cwe.cwe_id==cwe).first_or_none()
            if not cwe_obj:
                info(
                    f"{cwe} detected in {cve.cve_id} but not existing in database, adding it..."
                )
                cwe_obj = await Cwe(cwe_id=cwe).save()

        # Add the CPEs
        vendors_products = vendor_product_from_cpes(
            nested_lookup("cpe23Uri", cve_json["configurations"])
        )
        for vendor, products in vendors_products.items():
            v_obj = await Vendor.find(Vendor.name==vendor).first_or_none()

            # Create the vendor
            if not v_obj:
                v_obj = await Vendor(name=vendor).save(link_rule=WriteRules.WRITE)

            # Create the products
            for product in products:
                p_obj = await Product.find(Product.name==product, Product.vendor_id==str(v_obj.id)).first_or_none()
                if not p_obj:
                    p_obj = await Product(name=product, vendor_id=str(v_obj.id)).save()
                    vendor_products = list(set([*v_obj.products, p_obj]))
                    print(vendor_products)
                    v_obj.products = vendor_products
                    await v_obj.save(link_rule=WriteRules.WRITE)

        return cve
