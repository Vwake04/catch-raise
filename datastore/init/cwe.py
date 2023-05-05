from io import BytesIO
from zipfile import ZipFile

import requests
import untangle

from datastore.init.utils import header, info, timed_operation
from datastore.models.cwe import Cwe

# from opencve.extensions import db
# from opencve.models import get_uuid

MITRE_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"


async def run():
    """
    Import the CWE list.
    """
    header("Importing CWE list...")

    # Download the file
    with timed_operation("Downloading {}...".format(MITRE_CWE_URL)):
        resp = requests.get(MITRE_CWE_URL).content

    # Parse weaknesses
    with timed_operation("Parsing cwes..."):
        z = ZipFile(BytesIO(resp))
        raw = z.open(z.namelist()[0]).read()
        obj = untangle.parse(raw.decode("utf-8"))
        weaknesses = obj.Weakness_Catalog.Weaknesses.Weakness
        categories = obj.Weakness_Catalog.Categories.Category

    # Create the objects
    cwes = {}
    with timed_operation("Creating mappings..."):
        for c in weaknesses + categories:
            cwes[c["ID"]] = Cwe(
                cwe_id=f"CWE-{c['ID']}",
                name=c["Name"],
                description=c.Description.cdata
                if hasattr(c, "Description")
                else c.Summary.cdata,
            )

    # Insert the objects in database
    with timed_operation("Inserting CWE..."):
        await Cwe.insert_many(cwes.values())

    info("{} CWE imported.".format(len(cwes)))
    del cwes
