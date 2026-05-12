from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from domain.vulnerabilityDomain import Vulnerability


def parse_iso_month(date_str: Optional[str]) -> Optional[str]:
    if not date_str:
        return None
    try:
        if date_str.endswith("Z"):
            date_str = date_str[:-1]
        parsed = datetime.fromisoformat(date_str)
        return parsed.strftime("%Y-%m")
    except ValueError:
        return None


def group_by_month(vulns: List[Vulnerability], date_field: str) -> Dict[str, int]:
    counts = Counter()
    for vuln in vulns:
        date_value = getattr(vuln, date_field, None)
        month = parse_iso_month(date_value)
        if month:
            counts[month] += 1
    return dict(sorted(counts.items()))


def find_significant_months(counts: Dict[str, int]) -> List[Tuple[str, int, float]]:
    if not counts:
        return []
    values = list(counts.values())
    avg = sum(values) / len(values)
    result = []
    for month, count in sorted(counts.items()):
        ratio = count / avg if avg else 0.0
        if ratio >= 1.5:
            result.append((month, count, ratio))
    return result


def parse_cpe_vendor_product(cpe: str) -> Optional[str]:
    if not cpe or not cpe.startswith("cpe:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 6:
        return None
    part = parts[2]
    vendor = parts[3]
    product = parts[4]
    return f"{part}:{vendor}:{product}"


def rank_cpes(vulns: List[Vulnerability], top: int = 10) -> List[Tuple[str, int]]:
    counts = Counter()
    for vuln in vulns:
        for cpe in vuln.cpes:
            key = parse_cpe_vendor_product(cpe)
            if key:
                counts[key] += 1
    return counts.most_common(top)


def rank_cwes(vulns: List[Vulnerability], top: int = 10) -> List[Tuple[str, int]]:
    counts = Counter()
    for vuln in vulns:
        for cwe in vuln.cwes:
            if cwe:
                counts[cwe] += 1
    return counts.most_common(top)


def map_cve_to_cwes(vulns: List[Vulnerability]) -> Dict[str, List[str]]:
    return {v.id: sorted(set(v.cwes)) for v in vulns if v.cwes}


def count_cves_per_cwe(vulns: List[Vulnerability]) -> Dict[str, int]:
    counts = Counter()
    for vuln in vulns:
        for cwe in set(vuln.cwes):
            if cwe:
                counts[cwe] += 1
    return dict(counts)


def generate_analysis_report(name: str, vulns: List[Vulnerability]) -> Dict:
    published = group_by_month(vulns, "published_date")
    modified = group_by_month(vulns, "last_modified_date")
    trend_published = find_significant_months(published)
    trend_modified = find_significant_months(modified)
    cwe_rank = rank_cwes(vulns, top=10)
    cpe_rank = rank_cpes(vulns, top=10)
    cve_cwe_map = map_cve_to_cwes(vulns)
    return {
        "source": name,
        "vulnerability_count": len(vulns),
        "published_by_month": published,
        "last_modified_by_month": modified,
        "significant_published_months": trend_published,
        "significant_modified_months": trend_modified,
        "cwe_rank": cwe_rank,
        "cpe_rank": cpe_rank,
        "cve_cwe_map": cve_cwe_map,
        "cwe_vulnerability_count": count_cves_per_cwe(vulns),
    }


def print_analysis_summary(report: Dict) -> None:
    print(f"\nANÁLISIS: {report['source']}")
    print(f"Total de vulnerabilidades analizadas: {report['vulnerability_count']}")
    print("Publicación por mes:")
    for month, count in report["published_by_month"].items():
        print(f"  {month}: {count}")
    print("Última modificación por mes:")
    for month, count in report["last_modified_by_month"].items():
        print(f"  {month}: {count}")
    if report["significant_published_months"]:
        print("Meses con cambio de tendencia en publicación:")
        for month, count, ratio in report["significant_published_months"]:
            print(f"  {month}: {count} vulnerabilidades (x{ratio:.2f} sobre el promedio)")
    if report["significant_modified_months"]:
        print("Meses con cambio de tendencia en modificación:")
        for month, count, ratio in report["significant_modified_months"]:
            print(f"  {month}: {count} vulnerabilidades (x{ratio:.2f} sobre el promedio)")
    print("Ranking CWE:")
    for cwe, count in report["cwe_rank"]:
        print(f"  {cwe}: {count}")
    print("Ranking CPE (plataformas/productos):")
    for cpe, count in report["cpe_rank"]:
        print(f"  {cpe}: {count}")
    print("CVE vs CWE:")
    for cve, cwes in report["cve_cwe_map"].items():
        print(f"  {cve}: {cwes}")
