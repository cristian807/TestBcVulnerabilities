import requests
import json
from domain.vulnerabilityDomain import Vulnerability
from typing import List

class NucleiCvesRepository:
    URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"

    def get_vulnerabilities(self) -> List[Vulnerability]:
        response = requests.get(self.URL)
        text = response.text
        
        # Intentar parsear como JSON array
        try:
            data = response.json()
        except json.JSONDecodeError:
            # Si falla, intentar parsear como JSONL (una línea por objeto)
            data = []
            for line in text.strip().split('\n'):
                if line.strip():
                    try:
                        data.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        vulns = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    vulns.append(Vulnerability(
                        id=item.get("id", ""),
                        description=item.get("description", ""),
                        source="NUCLEI"
                    ))
        return vulns
