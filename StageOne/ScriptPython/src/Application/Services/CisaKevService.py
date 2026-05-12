from typing import List
from domain.vulnerabilityDomain import Vulnerability

class FetchCisaKevUseCase:
    def __init__(self, repository):
        self.repository = repository

    def execute(self) -> List[Vulnerability]:
        return self.repository.get_vulnerabilities()
