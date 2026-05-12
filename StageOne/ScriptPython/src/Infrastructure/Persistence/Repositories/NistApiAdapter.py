import requests
from domain.vulnerabilityDomain import Vulnerability
from typing import Optional

class NistApiAdapter:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

    @staticmethod
    def enrich_vulnerability(vuln: Vulnerability) -> Vulnerability:
        url = NistApiAdapter.BASE_URL + vuln.id
        response = requests.get(url)
        if response.status_code != 200:
            return vuln
        data = response.json()
        if not data.get("vulnerabilities"):
            return vuln
        nist_vuln = data["vulnerabilities"][0]["cve"]
        # Descripción
        descriptions = nist_vuln.get("descriptions", [])
        if descriptions:
            vuln.description = descriptions[0].get("value")
        # Fechas
        vuln.published_date = nist_vuln.get("published")
        vuln.last_modified_date = nist_vuln.get("lastModified")
        # Métricas CVSS
        metrics = nist_vuln.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]
            vuln.cvss_v31 = cvss
            vuln.base_score = cvss["cvssData"].get("baseScore")
            vuln.base_severity = cvss["cvssData"].get("baseSeverity")
            vuln.vector_string = cvss["cvssData"].get("vectorString")
            vuln.exploitability_score = cvss.get("exploitabilityScore")
            vuln.impact_score = cvss.get("impactScore")
        if "cvssMetricV2" in metrics:
            vuln.cvss_v2 = metrics["cvssMetricV2"][0]
        # CWE
        weaknesses = nist_vuln.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                vuln.cwes.append(desc.get("value"))
        # CPE
        cpes = set()
        for config in nist_vuln.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    cpes.add(cpe.get("criteria"))
        vuln.cpes = list(cpes)
        return vuln
