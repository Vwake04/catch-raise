import gzip
import json
from io import BytesIO

import arrow
import requests

from beanie import WriteRules, PydanticObjectId
from datastore.models.cve import Cve
from datastore.models.vendors import Vendor
from datastore.models.products import Product
from datastore.init.utils import header, info, timed_operation
from datastore.utilities.util import (
    get_slug, get_uuid, get_cwes_list, 
    vendor_product_from_cpes, 
    flatten_vendors_list, 
)


NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"


async def run():
    """
    Import the CVE list.
    """
    mappings = {"vendors": {}, "products": {}}

    from datastore.init import CURRENT_YEAR, CVE_FIRST_YEAR

    for year in range(CVE_FIRST_YEAR, CURRENT_YEAR + 1):
        header("Importing CVE for {}".format(year))
        mappings.update({"cves": 0, "changes": []})

        # Download the file
        url = NVD_CVE_URL.format(year=year)
        with timed_operation("Downloading {}...".format(url)):
            resp = requests.get(url).content

        # Parse the XML elements
        with timed_operation("Parsing JSON elements..."):
            raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
            del resp
            items = json.loads(raw.decode("utf-8"))["CVE_Items"]
            del raw

        with timed_operation("Creating model objects..."):

            for item in items:
                # cve_db_id = get_uuid()
                summary = item["cve"]["description"]["description_data"][0]["value"]
                cvss2 = (
                    item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                    if "baseMetricV2" in item["impact"]
                    else None
                )
                cvss3 = (
                    item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                    if "baseMetricV3" in item["impact"]
                    else None
                )

                # Construct CWE and CPE lists
                cwes = get_cwes_list(
                    item["cve"]["problemtype"]["problemtype_data"][0]["description"]
                )
                cpes = vendor_product_from_cpes(item["configurations"])
                vendors = flatten_vendors_list(cpes)

                await Cve(
                    cve_id=item["cve"]["CVE_data_meta"]["ID"],
                    summary=summary,
                    raw_json=item,
                    vendors=vendors,
                    cwes=cwes,
                    cvss2=cvss2,
                    cvss3=cvss3,
                    created_at=arrow.get(item["publishedDate"]).datetime,
                    updated_at=arrow.get(item["lastModifiedDate"]).datetime,
                ).save()
                mappings["cves"] += 1

                # Create the vendors and their products
                for vendor, products in cpes.items():

                    # Create the vendor
                    if vendor not in mappings["vendors"].keys():
                        mappings["vendors"][vendor] = Vendor(id=PydanticObjectId(), name=vendor)

                    for product in products:
                        if get_slug(vendor, product) not in mappings["products"]:
                            product_t = Product(
                                id=PydanticObjectId(),
                                name=product,
                                vendor_id=str(mappings["vendors"][vendor].id),
                            )
                            mappings["products"][get_slug(vendor, product)] = product_t

                            # Adding product to vendor's product list
                            vendor_products = mappings["vendors"][vendor].products
                            if product_t not in vendor_products:
                                vendor_products.append(product_t)
                            mappings["vendors"][vendor].products = list(vendor_products)

        info("{} CVE imported.".format(mappings["cves"]))

        # Free the memory after each processed year
        del mappings["cves"]
        del mappings["changes"]

    return mappings
