from datastore.models.cwe import Cwe
from datastore.checks import BaseCheck
from datastore.utilities.util import info


class Cwes(BaseCheck):
    async def execute(self):
        old = self.cve_obj.cwes
        new = [
            c["value"]
            for c in self.cve_json["cve"]["problemtype"]["problemtype_data"][0][
                "description"
            ]
        ]

        payload = {
            "added": list(set(new) - set(old)),
            "removed": list(set(old) - set(new)),
        }

        # It's possible that a CVE links a CWE not yet defined in database.
        # In this case we'll save it in the `cwes` table and a periodic task
        # will populate later its name and description using the MITRE file.
        for cwe_id in payload["added"]:
            cwe = await Cwe.find(Cwe.cwe_id==cwe_id).first_or_none()

            if not cwe:
                info(
                    f"{cwe_id} detected in {self.cve_obj.cve_id} but not existing in database, adding it..."
                )
                cwe = await Cwe(cwe_id=cwe_id).save()

        # If the list of CWE changed
        if payload["added"] or payload["removed"]:

            # Save the new list
            self.cve_obj.cwes = new
            await self.cve_obj.save()

        return None
