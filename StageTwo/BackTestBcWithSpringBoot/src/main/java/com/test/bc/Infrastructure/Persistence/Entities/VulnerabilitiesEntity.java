package com.test.bc.Infrastructure.Persistence.Entities;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "vulnerabilities")
public class VulnerabilitiesEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "cve_id", nullable = false, unique = true, length = 64)
	private String cveId;

	@Column(nullable = false, length = 255)
	private String title;

	@Column(columnDefinition = "TEXT")
	private String description;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 16)
	private SeverityLevel severity;

	@Column(name = "cvss_score", precision = 4, scale = 1)
	private BigDecimal cvssScore;

	@Column(name = "cvss_vector", length = 255)
	private String cvssVector;

	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 16)
	private VulnerabilityStatus status;

	@Column(name = "affected_product", length = 255)
	private String affectedProduct;

	@Column(name = "affected_vendor", length = 255)
	private String affectedVendor;

	@Column(name = "affected_version", length = 255)
	private String affectedVersion;

	@Column(columnDefinition = "TEXT")
	private String remediation;

	@Column(name = "published_at")
	private OffsetDateTime publishedAt;

	@Column(name = "source_updated_at")
	private OffsetDateTime sourceUpdatedAt;

	@CreationTimestamp
	@Column(name = "created_at", nullable = false, updatable = false)
	private OffsetDateTime createdAt;

	@UpdateTimestamp
	@Column(name = "modified_at", nullable = false)
	private OffsetDateTime modifiedAt;

	@OneToMany(mappedBy = "vulnerability", cascade = CascadeType.ALL, orphanRemoval = true)
	private List<VulnerabilitySourceEntity> sources = new ArrayList<>();

	public void setSources(List<VulnerabilitySourceEntity> newSources) {
		sources.clear();
		if (newSources == null) {
			return;
		}
		for (VulnerabilitySourceEntity source : newSources) {
			source.setVulnerability(this);
			sources.add(source);
		}
	}
}
