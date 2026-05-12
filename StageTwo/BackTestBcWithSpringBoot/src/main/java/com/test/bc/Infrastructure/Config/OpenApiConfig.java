package com.test.bc.Infrastructure.Config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

	@Bean
	public OpenAPI vulnerabilitiesOpenApi() {
		return new OpenAPI()
				.info(new Info()
						.title("Vulnerabilities API")
						.description("API para gestion de vulnerabilidades CISA y Nuclei")
						.version("v1")
						.contact(new Contact()
								.name("Security Team")
								.email("security@example.com"))
						.license(new License()
								.name("Internal Use")
								.url("https://example.com/license")));
	}
}
