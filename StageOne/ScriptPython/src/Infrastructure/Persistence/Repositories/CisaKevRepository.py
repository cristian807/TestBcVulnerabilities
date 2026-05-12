import requests
from domain.vulnerabilityDomain import Vulnerability
from typing import List

class CisaKevRepository:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def get_vulnerabilities(self) -> List[Vulnerability]:
        response = requests.get(self.URL)
        data = response.json()
        vulns = []
        for item in data.get("vulnerabilities", []):
            vulns.append(Vulnerability(
                id=item.get("cveID", ""),
                description=item.get("vulnerabilityName", ""),
                source="CISA_KEV"
            ))
        return vulns
