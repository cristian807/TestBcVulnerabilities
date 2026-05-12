package com.test.bc.Application.Dtos.Requests;

import com.test.bc.Infrastructure.Persistence.Entities.SeverityLevel;
import com.test.bc.Infrastructure.Persistence.Entities.SourceType;
import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilityStatus;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

public record VulnerabilitiesRequestDto(
	String cveId,
	String title,
	String description,
	SeverityLevel severity,
	BigDecimal cvssScore,
	String cvssVector,
	VulnerabilityStatus status,
	String affectedProduct,
	String affectedVendor,
	String affectedVersion,
	String remediation,
	OffsetDateTime publishedAt,
	OffsetDateTime sourceUpdatedAt,
	List<VulnerabilitySourceRequestDto> sources
) {

	public record VulnerabilitySourceRequestDto(
		SourceType sourceType,
		String sourceId,
		String templateId,
		String referenceUrl
	) {
	}
}

