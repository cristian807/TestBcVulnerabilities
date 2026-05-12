package com.test.bc.Domain.Entities;

import com.test.bc.Infrastructure.Persistence.Entities.SeverityLevel;
import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilityStatus;
import lombok.Builder;
import lombok.Getter;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

@Getter
@Builder
public class VulnerabilitieDomain {
    private Long id;

    private String cveId;

    private String title;

    private String description;

    private SeverityLevel severity;

    private BigDecimal cvssScore;

    private String cvssVector;

    private VulnerabilityStatus status;

    private String affectedProduct;

    private String affectedVendor;

    private String affectedVersion;

    private String remediation;

    private OffsetDateTime publishedAt;

    private OffsetDateTime sourceUpdatedAt;

    private OffsetDateTime createdAt;

    private OffsetDateTime modifiedAt;

    private List<VulnerabilitieSoruceDomain> sources;
}
