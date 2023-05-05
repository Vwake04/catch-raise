from datastore.checks import BaseCheck


class Summary(BaseCheck):
    async def execute(self):
        summary = self.cve_json["cve"]["description"]["description_data"][0]["value"]

        # Check if the summary has changed
        if self.cve_obj.summary != summary:
            # Replace it in the CVE
            old = self.cve_obj.summary
            self.cve_obj.summary = summary
            await self.cve_obj.save()
