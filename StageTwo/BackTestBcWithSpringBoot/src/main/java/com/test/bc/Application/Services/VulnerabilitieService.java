package com.test.bc.Application.Services;

import com.fasterxml.jackson.databind.JsonNode;
import com.test.bc.Application.Dtos.Requests.VulnerabilitiesRequestDto;
import com.test.bc.Application.Dtos.Responses.VulnerabilitiesReponseDto;
import com.test.bc.Application.Dtos.Responses.VulnerabilityCrudResponseDto;
import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilitiesEntity;
import com.test.bc.Infrastructure.Persistence.Entities.VulnerabilitySourceEntity;
import com.test.bc.Domain.Repositories.VulnerabilitiesRepositoryDomain;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class VulnerabilitieService {

	@Value("${nvd.cve.url}")
	private String nvdCveUrl;

	private final RestClient restClient;
	private final VulnerabilitiesRepositoryDomain vulnerabilitiesRepositoryDomain;

	public VulnerabilitieService(RestClient.Builder restClientBuilder,
							VulnerabilitiesRepositoryDomain vulnerabilitiesRepositoryDomain) {
		this.restClient = restClientBuilder.build();
		this.vulnerabilitiesRepositoryDomain = vulnerabilitiesRepositoryDomain;
	}

	public List<VulnerabilityCrudResponseDto> findAll() {
		return vulnerabilitiesRepositoryDomain.findAll().stream()
				.sorted(Comparator.comparing(VulnerabilitiesEntity::getId))
				.map(this::toCrudResponse)
				.toList();
	}

	public VulnerabilityCrudResponseDto findById(Long id) {
		return vulnerabilitiesRepositoryDomain.findById(id)
				.map(this::toCrudResponse)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Vulnerabilidad no encontrada"));
	}

	public VulnerabilityCrudResponseDto create(VulnerabilitiesRequestDto request) {
		validateRequest(request);

		if (vulnerabilitiesRepositoryDomain.existsByCveId(request.cveId())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "CveId ya existe");
		}

		VulnerabilitiesEntity vulnerability = new VulnerabilitiesEntity();
		applyRequest(vulnerability, request);

		return toCrudResponse(vulnerabilitiesRepositoryDomain.save(vulnerability));
	}

	public VulnerabilityCrudResponseDto update(Long id, VulnerabilitiesRequestDto request) {
		validateRequest(request);

		VulnerabilitiesEntity vulnerability = vulnerabilitiesRepositoryDomain.findById(id)
				.orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Vulnerabilidad no encontrada"));

		if (vulnerabilitiesRepositoryDomain.existsByCveIdAndIdNot(request.cveId(), id)) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "CveId ya existe");
		}

		applyRequest(vulnerability, request);
		return toCrudResponse(vulnerabilitiesRepositoryDomain.save(vulnerability));
	}

	public void delete(Long id) {
		if (!vulnerabilitiesRepositoryDomain.existsById(id)) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Vulnerabilidad no encontrada");
		}
		vulnerabilitiesRepositoryDomain.deleteById(id);
	}

	public VulnerabilitiesReponseDto searchByCveId(String cveId) {
		if (!StringUtils.hasText(cveId)) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CveId es requerido");
		}

		JsonNode root = restClient.get()
				.uri(nvdCveUrl + "?cveId={cveId}", cveId)
				.retrieve()
				.body(JsonNode.class);

		if (root == null || root.path("totalResults").asInt(0) == 0) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "CVE no encontrada");
		}

		JsonNode cve = root.path("vulnerabilities").path(0).path("cve");

		// Try cvssMetricV31 first, fall back to cvssMetricV2
		JsonNode cvssMetrics = cve.path("metrics");
		JsonNode cvssV31Entry = cvssMetrics.path("cvssMetricV31").path(0);
		JsonNode cvssV2Entry  = cvssMetrics.path("cvssMetricV2").path(0);
		boolean useV31 = !cvssV31Entry.isMissingNode() && !cvssV31Entry.isNull();
		JsonNode cvssData     = useV31 ? cvssV31Entry.path("cvssData") : cvssV2Entry.path("cvssData");
		String   baseSeverity = useV31
				? cvssV31Entry.path("cvssData").path("baseSeverity").asText()
				: cvssV2Entry.path("baseSeverity").asText();

		String description = extractEnglishDescription(cve.path("descriptions"));
		String affectedVersions = extractAffectedVersions(cve.path("configurations"));
		String[] softwareAndVendor = extractSoftwareAndVendor(cve.path("configurations"));

		return new VulnerabilitiesReponseDto(
				cve.path("id").asText(cveId),
				softwareAndVendor[0],
				softwareAndVendor[1],
				affectedVersions,
				extractWeaknesses(cve.path("weaknesses")),
				description,
				cve.path("published").asText(),
				cve.path("lastModified").asText(),
				cve.path("vulnStatus").asText(),
				new VulnerabilitiesReponseDto.CvssDto(
						cvssData.path("version").asText(),
						cvssData.path("baseScore").asDouble(),
						baseSeverity,
						cvssData.path("vectorString").asText(),
						cvssData.path("attackVector").asText(useV31 ? "" : cvssData.path("accessVector").asText()),
						cvssData.path("attackComplexity").asText(useV31 ? "" : cvssData.path("accessComplexity").asText()),
						cvssData.path("privilegesRequired").asText(useV31 ? "" : cvssData.path("authentication").asText()),
						cvssData.path("userInteraction").asText(),
						cvssData.path("confidentialityImpact").asText(),
						cvssData.path("integrityImpact").asText(),
						cvssData.path("availabilityImpact").asText()
				),
				buildImpact(cvssData, baseSeverity, description),
				!looksLikeNoPatch(description),
				extractReferences(cve.path("references"))
		);
	}

	private VulnerabilitiesReponseDto.ImpactDto buildImpact(JsonNode cvssData, String baseSeverity, String description) {
		String availabilityImpact    = cvssData.path("availabilityImpact").asText("NONE");
		String attackVector          = cvssData.path("attackVector").asText(
				cvssData.path("accessVector").asText("NONE"));
		String confidentialityImpact = cvssData.path("confidentialityImpact").asText("NONE");
		String integrityImpact       = cvssData.path("integrityImpact").asText("NONE");

		boolean serviceCrash     = !"NONE".equalsIgnoreCase(availabilityImpact)
				|| containsIgnoreCase(description, "crash");
		boolean remoteExploitable = "NETWORK".equalsIgnoreCase(attackVector);
		boolean dataExposure     = !"NONE".equalsIgnoreCase(confidentialityImpact);
		boolean dataModification = !"NONE".equalsIgnoreCase(integrityImpact);

		return new VulnerabilitiesReponseDto.ImpactDto(
				serviceCrash,
				remoteExploitable,
				dataExposure,
				dataModification
		);
	}

	private List<String> extractWeaknesses(JsonNode weaknesses) {
		Set<String> values = new LinkedHashSet<>();
		if (weaknesses.isArray()) {
			for (JsonNode weakness : weaknesses) {
				JsonNode descriptions = weakness.path("description");
				if (descriptions.isArray()) {
					for (JsonNode desc : descriptions) {
						String value = desc.path("value").asText();
						if (StringUtils.hasText(value)) {
							values.add(value);
						}
					}
				}
			}
		}
		return new ArrayList<>(values);
	}

	private List<String> extractReferences(JsonNode references) {
		Set<String> values = new LinkedHashSet<>();
		if (references.isArray()) {
			for (JsonNode ref : references) {
				String url = ref.path("url").asText();
				if (StringUtils.hasText(url)) {
					values.add(url);
				}
			}
		}
		return new ArrayList<>(values);
	}

	private String extractEnglishDescription(JsonNode descriptions) {
		if (descriptions.isArray()) {
			for (JsonNode description : descriptions) {
				if ("en".equalsIgnoreCase(description.path("lang").asText())) {
					return description.path("value").asText("");
				}
			}
			if (descriptions.size() > 0) {
				return descriptions.path(0).path("value").asText("");
			}
		}
		return "";
	}

	private String extractAffectedVersions(JsonNode configurations) {
		JsonNode cpeMatch = firstCpeMatch(configurations);
		if (cpeMatch.isMissingNode()) {
			return "";
		}

		String endIncluding   = cpeMatch.path("versionEndIncluding").asText();
		String endExcluding   = cpeMatch.path("versionEndExcluding").asText();
		String startIncluding = cpeMatch.path("versionStartIncluding").asText();
		String startExcluding = cpeMatch.path("versionStartExcluding").asText();

		if (StringUtils.hasText(endIncluding)) {
			return "<= " + endIncluding;
		}
		if (StringUtils.hasText(endExcluding)) {
			return "< " + endExcluding;
		}
		if (StringUtils.hasText(startIncluding)) {
			return ">= " + startIncluding;
		}
		if (StringUtils.hasText(startExcluding)) {
			return "> " + startExcluding;
		}

		String criteria = cpeMatch.path("criteria").asText();
		if (StringUtils.hasText(criteria)) {
			String[] segments = criteria.split(":");
			if (segments.length > 5) {
				String version = segments[5];
				if (StringUtils.hasText(version) && !"*".equals(version) && !"-".equals(version)) {
					return version;
				}
			}
		}
		return "";
	}

	private String[] extractSoftwareAndVendor(JsonNode configurations) {
		JsonNode cpeMatch = firstCpeMatch(configurations);
		if (cpeMatch.isMissingNode()) {
			return new String[]{"", ""};
		}

		String criteria = cpeMatch.path("criteria").asText();
		String[] segments = criteria.split(":");
		if (segments.length < 6) {
			return new String[]{"", ""};
		}

		String vendor = formatCpePart(segments[3]);
		String software = formatCpePart(segments[4]);

		return new String[]{software, vendor};
	}

	private JsonNode firstCpeMatch(JsonNode configurations) {
		if (!configurations.isArray()) {
			return com.fasterxml.jackson.databind.node.MissingNode.getInstance();
		}

		for (JsonNode config : configurations) {
			JsonNode nodes = config.path("nodes");
			if (!nodes.isArray()) {
				continue;
			}
			for (JsonNode node : nodes) {
				JsonNode cpeMatches = node.path("cpeMatch");
				if (!cpeMatches.isArray()) {
					continue;
				}
				for (JsonNode cpeMatch : cpeMatches) {
					if (cpeMatch.path("vulnerable").asBoolean(false)) {
						return cpeMatch;
					}
				}
			}
		}

		return com.fasterxml.jackson.databind.node.MissingNode.getInstance();
	}

	private String formatCpePart(String value) {
		if (!StringUtils.hasText(value) || "*".equals(value)) {
			return "";
		}

		String normalized = value.replace('_', ' ').replace('-', ' ').trim();
		String[] tokens = normalized.split("\\s+");
		List<String> titleTokens = new ArrayList<>();
		for (String token : tokens) {
			if (token.isEmpty()) {
				continue;
			}
			String lower = token.toLowerCase(Locale.ROOT);
			titleTokens.add(Character.toUpperCase(lower.charAt(0)) + lower.substring(1));
		}
		return String.join(" ", titleTokens);
	}

	private boolean looksLikeNoPatch(String description) {
		return containsIgnoreCase(description, "no fix")
				|| containsIgnoreCase(description, "no hay ninguna solucion")
				|| containsIgnoreCase(description, "there's no fix yet");
	}

	private boolean containsIgnoreCase(String value, String token) {
		if (value == null || token == null) {
			return false;
		}
		return value.toLowerCase(Locale.ROOT).contains(token.toLowerCase(Locale.ROOT));
	}

	private void validateRequest(VulnerabilitiesRequestDto request) {
		if (request == null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "request body is required");
		}
		if (!StringUtils.hasText(request.cveId())) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cveId is required");
		}
		if (!StringUtils.hasText(request.title())) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "title is required");
		}
		if (request.severity() == null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "severity is required");
		}
		if (request.status() == null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "status is required");
		}
		if (request.sources() == null || request.sources().isEmpty()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "at least one source is required");
		}
		for (VulnerabilitiesRequestDto.VulnerabilitySourceRequestDto source : request.sources()) {
			if (source.sourceType() == null) {
				throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "sourceType is required for each source");
			}
		}
	}

	private void applyRequest(VulnerabilitiesEntity vulnerability, VulnerabilitiesRequestDto request) {
		vulnerability.setCveId(request.cveId());
		vulnerability.setTitle(request.title());
		vulnerability.setDescription(request.description());
		vulnerability.setSeverity(request.severity());
		vulnerability.setCvssScore(request.cvssScore());
		vulnerability.setCvssVector(request.cvssVector());
		vulnerability.setStatus(request.status());
		vulnerability.setAffectedProduct(request.affectedProduct());
		vulnerability.setAffectedVendor(request.affectedVendor());
		vulnerability.setAffectedVersion(request.affectedVersion());
		vulnerability.setRemediation(request.remediation());
		vulnerability.setPublishedAt(request.publishedAt());
		vulnerability.setSourceUpdatedAt(request.sourceUpdatedAt());

		List<VulnerabilitySourceEntity> sources = request.sources().stream()
				.map(sourceRequest -> {
					VulnerabilitySourceEntity sourceEntity = new VulnerabilitySourceEntity();
					sourceEntity.setSourceType(sourceRequest.sourceType());
					sourceEntity.setSourceId(sourceRequest.sourceId());
					sourceEntity.setTemplateId(sourceRequest.templateId());
					sourceEntity.setReferenceUrl(sourceRequest.referenceUrl());
					return sourceEntity;
				})
				.toList();

		vulnerability.setSources(sources);
	}

	private VulnerabilityCrudResponseDto toCrudResponse(VulnerabilitiesEntity vulnerability) {
		List<VulnerabilityCrudResponseDto.VulnerabilitySourceResponseDto> sources = vulnerability.getSources().stream()
				.map(source -> new VulnerabilityCrudResponseDto.VulnerabilitySourceResponseDto(
						source.getId(),
						source.getSourceType(),
						source.getSourceId(),
						source.getTemplateId(),
						source.getReferenceUrl()
				))
				.toList();

		return new VulnerabilityCrudResponseDto(
				vulnerability.getId(),
				vulnerability.getCveId(),
				vulnerability.getTitle(),
				vulnerability.getDescription(),
				vulnerability.getSeverity(),
				vulnerability.getCvssScore(),
				vulnerability.getCvssVector(),
				vulnerability.getStatus(),
				vulnerability.getAffectedProduct(),
				vulnerability.getAffectedVendor(),
				vulnerability.getAffectedVersion(),
				vulnerability.getRemediation(),
				vulnerability.getPublishedAt(),
				vulnerability.getSourceUpdatedAt(),
				vulnerability.getCreatedAt(),
				vulnerability.getModifiedAt(),
				sources
		);
	}
}
