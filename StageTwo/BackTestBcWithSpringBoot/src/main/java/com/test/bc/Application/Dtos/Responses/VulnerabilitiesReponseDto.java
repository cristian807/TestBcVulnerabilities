package com.test.bc.Application.Dtos.Responses;

import java.util.List;

public record VulnerabilitiesReponseDto(
	String cveId,
	String software,
	String vendor,
	String affectedVersions,
	List<String> vulnerabilityType,
	String description,
	String published,
	String lastModified,
	String status,
	CvssDto cvss,
	ImpactDto impact,
	boolean patchAvailable,
	List<String> references
) {

    public record CvssDto(
	    String version,
	    double score,
	    String severity,
	    String vector,
	    String attackVector,
	    String attackComplexity,
	    String privilegesRequired,
	    String userInteraction,
	    String confidentialityImpact,
	    String integrityImpact,
	    String availabilityImpact
    ) {
    }

    public record ImpactDto(
	    boolean serviceCrash,
	    boolean remoteExploitable,
	    boolean dataExposure,
	    boolean dataModification
    ) {
    }
}
