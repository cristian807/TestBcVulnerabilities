
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from Infrastructure.Persistence.Repositories.CisaKevRepository import CisaKevRepository
from Infrastructure.Persistence.Repositories.NucleiCvesRepository import NucleiCvesRepository
from Infrastructure.Persistence.Repositories.NistApiAdapter import NistApiAdapter
from Application.Services.CisaKevService import FetchCisaKevUseCase
from Application.Services.NucleiCvesService import FetchNucleiCvesUseCase
from Application.Services.AnalyzevulnerabilitieService import (
    generate_analysis_report, print_analysis_summary
)
import time
import json


def enrich_vulns_with_nist(vulns, limit=10):
    enriched = []
    for v in vulns[:limit]:
        try:
            enriched.append(NistApiAdapter.enrich_vulnerability(v))
            time.sleep(0.7)  # Evitar rate limit NIST
        except Exception as e:
            print(f"Error enriqueciendo {v.id}: {e}")
    return enriched

def print_structured(vulns):
    for v in vulns:
        print(f"CVE: {v.id}")
        print(f"  Descripción: {v.description}")
        print(f"  CVSS v3.1: {v.cvss_v31}")
        print(f"  CVSS v2: {v.cvss_v2}")
        print(f"  Exploitability Score: {v.exploitability_score}")
        print(f"  Impact Score: {v.impact_score}")
        print(f"  Base Score: {v.base_score}")
        print(f"  Base Severity: {v.base_severity}")
        print(f"  Vector String: {v.vector_string}")
        print(f"  CWE(s): {v.cwes}")
        print(f"  CPE(s): {v.cpes}")
        print(f"  Publicado: {v.published_date}")
        print(f"  Modificado: {v.last_modified_date}")
        print("---")

if __name__ == "__main__":
    cisa_usecase = FetchCisaKevUseCase(CisaKevRepository())
    nuclei_usecase = FetchNucleiCvesUseCase(NucleiCvesRepository())
    limit = 10

    print("\n" + "="*60)
    print("DESCARGANDO VULNERABILIDADES DE CISA KEV")
    print("="*60)

    cisa_vulns = cisa_usecase.execute()
    print(f"\nSE OBTUVIERON {len(cisa_vulns)} VULNERABILIDADES DE CISA KEV")
    

    print("\n" + "="*60)
    print("DESCARGANDO VULNERABILIDADES DE NUCLEI")
    print("="*60)
   
    nuclei_vulns = nuclei_usecase.execute()
    print(f"\nSE OBTUVIERON {len(nuclei_vulns)} VULNERABILIDADES DE NUCLEI")

    print("\n" + "="*60)
    print("CONSULTANDO DATOS DE NIST API")
    print("="*60)
    

    print(f"\nCONSULTANDO NIST API PARA ENRIQUECER CISA KEV {limit} VULNERABILIDADES")
    cisa_enriched = enrich_vulns_with_nist(cisa_vulns, limit)
    print(f"✓ CISA enriquecidas: {len(cisa_enriched)}")
    
    print(f"\nCONSULTANDO NIST API PARA ENRIQUECER NUCLEI {limit} VULNERABILIDADES")
    nuclei_enriched = enrich_vulns_with_nist(nuclei_vulns, limit)
    print(f"Nuclei enriquecidas: {len(nuclei_enriched)}")

    print("\n" + "="*60)
    print("VULNERABILIDADES ENRIQUECIDAS")
    print("="*60)
    
    print("\nCISA KEV Vulnerabilities:")
    print_structured(cisa_enriched)
    
    print("\nNuclei CVEs:")
    print_structured(nuclei_enriched)

    print("\n" + "="*60)
    print("ANÁLISIS DE TENDENCIAS Y RELACIONES")
    print("="*60)
    
    all_vulns = cisa_enriched + nuclei_enriched
    cisa_report = generate_analysis_report("CISA KEV", cisa_enriched)
    nuclei_report = generate_analysis_report("NUCLEI", nuclei_enriched)
    combined_report = generate_analysis_report("COMBINADO", all_vulns)
    
    print_analysis_summary(cisa_report)
    print_analysis_summary(nuclei_report)
    print_analysis_summary(combined_report)
