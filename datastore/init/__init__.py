import arrow
from datastore.models.cve import Cve
from datastore.models.metas import Metas
from datastore.init import cwe, cve, cpe
from datastore.init.utils import info, timed_operation


CURRENT_YEAR = arrow.now().year
CVE_FIRST_YEAR = 2002


async def init_import():
    """
    Import all the cwe, cves, and cpes
    """
    if await Cve.find().first_or_none():
        info("Data Already Imported.")
        return

    with timed_operation(
        "Importing CWEs, CVEs and its "
        "Corresponding Vendors and Products..."
    ):
        await cwe.run()
        vendors = await cve.run()
        await cpe.run(vendors)

    with timed_operation("Populating metas table..."):
        await Metas(name="nvd_last_sha256", value="default").save()
    
    info("Import Completed.")

    
    

