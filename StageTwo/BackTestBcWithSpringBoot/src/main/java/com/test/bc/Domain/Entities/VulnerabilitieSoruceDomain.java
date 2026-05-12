package com.test.bc.Domain.Entities;

import com.test.bc.Infrastructure.Persistence.Entities.SourceType;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class VulnerabilitieSoruceDomain {
    private Long id;

    private SourceType sourceType;

    private String sourceId;

    private String templateId;

    private String referenceUrl;
}
