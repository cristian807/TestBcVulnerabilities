package com.test.bc.Infrastructure.Persistence.Mappers;

import com.test.bc.Domain.Entities.VulnerabilitieDomain;
import com.test.bc.Domain.Entities.VulnerabilitieSoruceDomain;
import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilitiesEntity;
import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilitySourceEntity;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class VulnerabilitieMapper {

    public VulnerabilitieDomain toDomain(VulnerabilitiesEntity entity) {
        if (entity == null) {
            return null;
        }
        return VulnerabilitieDomain.builder()
                .id(entity.getId())
                .cveId(entity.getCveId())
                .title(entity.getTitle())
                .description(entity.getDescription())
                .severity(entity.getSeverity())
                .cvssScore(entity.getCvssScore())
                .cvssVector(entity.getCvssVector())
                .status(entity.getStatus())
                .affectedProduct(entity.getAffectedProduct())
                .affectedVendor(entity.getAffectedVendor())
                .affectedVersion(entity.getAffectedVersion())
                .remediation(entity.getRemediation())
                .publishedAt(entity.getPublishedAt())
                .sourceUpdatedAt(entity.getSourceUpdatedAt())
                .createdAt(entity.getCreatedAt())
                .modifiedAt(entity.getModifiedAt())
                .sources(toDomainSources(entity.getSources()))
                .build();
    }

    public VulnerabilitiesEntity toEntity(VulnerabilitieDomain domain) {
        if (domain == null) {
            return null;
        }
        VulnerabilitiesEntity entity = new VulnerabilitiesEntity();
        entity.setId(domain.getId());
        entity.setCveId(domain.getCveId());
        entity.setTitle(domain.getTitle());
        entity.setDescription(domain.getDescription());
        entity.setSeverity(domain.getSeverity());
        entity.setCvssScore(domain.getCvssScore());
        entity.setCvssVector(domain.getCvssVector());
        entity.setStatus(domain.getStatus());
        entity.setAffectedProduct(domain.getAffectedProduct());
        entity.setAffectedVendor(domain.getAffectedVendor());
        entity.setAffectedVersion(domain.getAffectedVersion());
        entity.setRemediation(domain.getRemediation());
        entity.setPublishedAt(domain.getPublishedAt());
        entity.setSourceUpdatedAt(domain.getSourceUpdatedAt());
        entity.setSources(toEntitySources(domain.getSources()));
        return entity;
    }

    private VulnerabilitieSoruceDomain toDomainSource(VulnerabilitySourceEntity source) {
        if (source == null) {
            return null;
        }
        return VulnerabilitieSoruceDomain.builder()
                .id(source.getId())
                .sourceType(source.getSourceType())
                .sourceId(source.getSourceId())
                .templateId(source.getTemplateId())
                .referenceUrl(source.getReferenceUrl())
                .build();
    }

    private List<VulnerabilitieSoruceDomain> toDomainSources(List<VulnerabilitySourceEntity> sources) {
        if (sources == null) {
            return Collections.emptyList();
        }
        return sources.stream()
                .map(this::toDomainSource)
                .collect(Collectors.toList());
    }

    private VulnerabilitySourceEntity toEntitySource(VulnerabilitieSoruceDomain source) {
        if (source == null) {
            return null;
        }
        VulnerabilitySourceEntity entity = new VulnerabilitySourceEntity();
        entity.setId(source.getId());
        entity.setSourceType(source.getSourceType());
        entity.setSourceId(source.getSourceId());
        entity.setTemplateId(source.getTemplateId());
        entity.setReferenceUrl(source.getReferenceUrl());
        return entity;
    }

    private List<VulnerabilitySourceEntity> toEntitySources(List<VulnerabilitieSoruceDomain> sources) {
        if (sources == null) {
            return Collections.emptyList();
        }
        return sources.stream()
                .map(this::toEntitySource)
                .collect(Collectors.toList());
    }
}

