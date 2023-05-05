import gzip
from io import BytesIO
import xml.etree.ElementTree

import requests
from cpe import CPE

from beanie import WriteRules, PydanticObjectId

from datastore.models.vendors import Vendor
from datastore.models.products import Product
from datastore.init.utils import header, info, timed_operation
from datastore.utilities.util import get_slug

NVD_CPE_URL = (
    "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"
)


async def run(mappings):
    """
    Import the Vendors and Products list.
    """
    header("Importing CPE list...")

    # Download the XML file
    with timed_operation("Downloading {}...".format(NVD_CPE_URL)):
        resp = requests.get(NVD_CPE_URL).content

    # Parse the XML elements
    with timed_operation("Parsing XML elements..."):
        raw = gzip.GzipFile(fileobj=BytesIO(resp))
        del resp
        items = set()
        for _, elem in xml.etree.ElementTree.iterparse(raw):
            if elem.tag.endswith("cpe23-item"):
                items.add(elem.get("name"))
            elem.clear()
        del raw

    # Create the objects
    with timed_operation("Creating mappings of Vendors and Products..."):
        for item in items:
            obj = CPE(item)
            vendor = obj.get_vendor()[0]
            product = obj.get_product()[0]

            if vendor not in mappings["vendors"].keys():
                mappings["vendors"][vendor] = Vendor(id=PydanticObjectId(), name=vendor)

            if get_slug(vendor, product) not in mappings["products"]:
                product_t = Product(
                    id=PydanticObjectId(),
                    name=product,
                    vendor_id=str(mappings["vendors"][vendor].id)
                )

                # Add to map
                mappings["products"][get_slug(vendor, product)] = product_t

                # Adding product to vendor's product list
                vendor_products = mappings["vendors"][vendor].products
                if product_t not in vendor_products:
                    vendor_products.append(product_t)
                mappings["vendors"][vendor].products = list(vendor_products)
        del items
    

    with timed_operation("Inserting Vendors and Products..."):
        await Product.insert_many(mappings["products"].values())
        await Vendor.insert_many(mappings["vendors"].values())

    info(
        "{} vendors and {} products imported.".format(
            len(mappings["vendors"]), len(mappings["products"])
        )
    )
    del mappings
