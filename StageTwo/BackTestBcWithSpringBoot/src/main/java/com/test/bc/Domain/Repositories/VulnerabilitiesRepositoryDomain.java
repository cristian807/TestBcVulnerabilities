package com.test.bc.Domain.Repositories;

import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilitiesEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VulnerabilitiesRepositoryDomain extends JpaRepository<VulnerabilitiesEntity, Long> {
	boolean existsByCveId(String cveId);

	boolean existsByCveIdAndIdNot(String cveId, Long id);
}
