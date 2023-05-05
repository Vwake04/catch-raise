"""
Common utility functions used across datastore 
"""
import uuid
import logging
from nested_lookup import nested_lookup


def _humanize_filter(s):
    return " ".join(map(lambda x: x.capitalize(), s.split("_")))


def vendor_product_from_cpes(conf):
    """
    Extracts and transforms CPE uris into
    dict, vendors with its list of products.
    :param conf: object
    """
    cpe_uris = nested_lookup("cpe23Uri", conf) if not isinstance(conf, list) else conf

    # [(vendor, product),....,(vendor, product)]
    cpes_t = list(set([tuple(cpe_uri.split(":")[3:5]) for cpe_uri in cpe_uris]))

    # Transform it into nested dictionnary
    cpes = {}
    for vendor, product in cpes_t:
        if vendor not in cpes:
            cpes[vendor] = []
        cpes[vendor].append(product)

    return cpes


def flatten_vendors_list(vendors):
    """
    Takes a list of nested vendors and products and flat them.
    """
    data = []
    for vendor, products in vendors.items():
        data.append(vendor)
        for product in products:
            data.append(f"{vendor}::{product}")
    return data


def get_cwes_list(problems):
    """
    Takes a list of problems and return the CWEs ID.
    """
    return list(set([p["value"] for p in problems]))


def get_slug(vendor, product=None):
    slug = vendor
    if product:
        slug += f"-{product}"
    return slug


def get_uuid():
    return str(uuid.uuid4())


def setup_logger(log_path: str = "datastore_"):
    # Create and configure logger
    logging.basicConfig(
        filename=f"{log_path}.log",
        format='[%(asctime)s] %(message)s',
        filemode='w'
    )
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    return logger
