import gzip
import json
import re
from io import BytesIO

import arrow
import requests
from datastore.models.cve import Cve
from datastore.checks import BaseCheck
from datastore.models.metas import Metas
from datastore.init.cve_util import CveUtil
from datastore.utilities.util import setup_logger


NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
NVD_MODIFIED_META_URL = (
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
)


async def has_changed():
    """
    Download the latest metadata
    And compares the last metadata
    """
    print("Downloading {}...".format(NVD_MODIFIED_META_URL))
    resp = requests.get(NVD_MODIFIED_META_URL)
    buf = BytesIO(resp.content).read().decode("utf-8")

    matches = re.match(r".*sha256:(\w{64}).*", buf, re.DOTALL)
    nvd_sha256 = matches.group(1)
    last_nvd256 = await Metas.find(Metas.name=="nvd_last_sha256").first_or_none()

    if last_nvd256 is None or nvd_sha256 != last_nvd256.value:
        print(
            "Found different hashes (old:{}, new:{}).".format(
                last_nvd256.value, nvd_sha256
            )
        )
        return last_nvd256, nvd_sha256
    else:
        print("DB is up to date.")
        return last_nvd256, None


def download_modified_items():
    """
    Download the lastest cve changes 
    """
    print("Downloading {}...".format(NVD_MODIFIED_URL))
    resp = requests.get(NVD_MODIFIED_URL).content
    raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
    items = json.loads(raw.decode("utf-8"))["CVE_Items"]
    return items


async def check_for_update(cve_json, task):
    """
    Existence of latest CVEs are checked,
    If present then the CVEs are updated
    Else new CVEs are added.
    """
    cve_id = cve_json["cve"]["CVE_data_meta"]["ID"]
    cve_obj = await Cve.find(Cve.cve_id==cve_id).first_or_none()

    # A new CVE has been added
    if not cve_obj:
        cve_obj = await CveUtil.create_cve(cve_json)
        print(f"{cve_id} created (ID: {cve_obj.id})")

    # Existing CVE has changed
    elif CveUtil.cve_has_changed(cve_obj, cve_json):
        print(f"{cve_obj.cve_id} has changed, parsing it...")

        # events = []
        checks = BaseCheck.__subclasses__()

        # Loop on each kind of check
        for check in checks:
            c = check(cve_obj, cve_json)
            c.execute()

        # Change the last updated date
        cve_obj.updated_at = arrow.get(cve_json["lastModifiedDate"]).datetime
        cve_obj.raw_json = cve_json
        await cve_obj.save()


async def handle_events():
    """
    Driver function for updating the CVEs
    """
    print("Checking Metas...")
    if not await Metas.find().count():
        print("Init has not yet initiated or completed.")
        return

    print("Checking for new events...")
    current_sum, new_sum = await has_changed()
    if not new_sum:
        return

    # Retrieve the list of modified CVEs
    print("Download modified CVEs...")
    items = download_modified_items()

    print("Checking {} CVEs...".format(len(items)))
    for item in items:
        await check_for_update(item, "task")

    print("CVEs checked, updating meta hash...")
    current_sum.value = new_sum
    await current_sum.save()
    print("Done, new meta is {}.".format(new_sum))
