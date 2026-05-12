package com.test.bc.Infrastructure.Persistence.Adapters;

import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilitiesEntity;
import com.test.bc.Infrastructure.Persistence.Repositories.VulnerabilitiesRepository;
import org.springframework.stereotype.Repository;


@Repository("vulnerabilitiesPersistenceAdapter")
public class VulnerabilitieAdapter {

    private final VulnerabilitiesRepository vulnerabilitiesRepository;

    public VulnerabilitieAdapter(VulnerabilitiesRepository vulnerabilitiesRepository) {
        this.vulnerabilitiesRepository = vulnerabilitiesRepository;
    }

    public <S extends VulnerabilitiesEntity> S save(S entity) {
        return vulnerabilitiesRepository.save(entity);
    }

    public void deleteById(Long id) {
        vulnerabilitiesRepository.deleteById(id);
    }

    public boolean existsByCveId(String cveId) {
        return vulnerabilitiesRepository.existsByCveId(cveId);
    }

    public boolean existsByCveIdAndIdNot(String cveId, Long id) {
        return vulnerabilitiesRepository.existsByCveIdAndIdNot(cveId, id);
    }
}

