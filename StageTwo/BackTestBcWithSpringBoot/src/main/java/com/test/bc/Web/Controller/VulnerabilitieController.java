package com.test.bc.Web.Controller;

import com.test.bc.Application.Dtos.Requests.VulnerabilitiesRequestDto;
import com.test.bc.Application.Dtos.Responses.VulnerabilitiesReponseDto;
import com.test.bc.Application.Dtos.Responses.VulnerabilityCrudResponseDto;
import com.test.bc.Application.Services.VulnerabilitieService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/vulnerabilities")
public class VulnerabilitieController {

	private final VulnerabilitieService vulnerabilitieService;

	public VulnerabilitieController(VulnerabilitieService vulnerabilitieService) {
		this.vulnerabilitieService = vulnerabilitieService;
	}

	@GetMapping
	public List<VulnerabilityCrudResponseDto> getAll() {
		return vulnerabilitieService.findAll();
	}

	@GetMapping("/{id}")
	public VulnerabilityCrudResponseDto getById(@PathVariable Long id) {
		return vulnerabilitieService.findById(id);
	}

	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public VulnerabilityCrudResponseDto create(@RequestBody VulnerabilitiesRequestDto request) {
		return vulnerabilitieService.create(request);
	}

	@PutMapping("/{id}")
	public VulnerabilityCrudResponseDto update(@PathVariable Long id,
									   @RequestBody VulnerabilitiesRequestDto request) {
		return vulnerabilitieService.update(id, request);
	}

	@DeleteMapping("/{id}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public void delete(@PathVariable Long id) {
		vulnerabilitieService.delete(id);
	}

	@GetMapping("/search")
	public VulnerabilitiesReponseDto search(@RequestParam("cveId") String cveId) {
		return vulnerabilitieService.searchByCveId(cveId);
	}
}
