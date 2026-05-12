import { CommonModule } from '@angular/common';
import { Component, OnInit, computed, inject, signal } from '@angular/core';
import {
  FormBuilder,
  ReactiveFormsModule,
  Validators,
  type FormControl,
  type FormGroup,
} from '@angular/forms';
import { finalize } from 'rxjs';
import {
  SeverityLevel,
  SourceType,
  Vulnerability,
  VulnerabilitySearchResponse,
  VulnerabilityStatus,
} from '../../../domain/models/vulnerability.model';
import { VulnerabilityUseCasesService } from '../../../application/services/vulnerability-use-cases.service';
import { VulnerabilityDetailModalComponent } from '../../components/vulnerability-detail-modal/vulnerability-detail-modal.component';

type VulnerabilityForm = FormGroup<{
  cveId: FormControl<string>;
  title: FormControl<string>;
  severity: FormControl<SeverityLevel>;
  status: FormControl<VulnerabilityStatus>;
  cvssScore: FormControl<number | null>;
  affectedProduct: FormControl<string>;
  affectedVendor: FormControl<string>;
  affectedVersion: FormControl<string>;
  remediation: FormControl<string>;
  sourceTypes: FormControl<SourceType[]>;
}>;

@Component({
  selector: 'app-vulnerabilities-page',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, VulnerabilityDetailModalComponent],
  templateUrl: './vulnerabilities-page.component.html',
  styleUrl: './vulnerabilities-page.component.css',
})
export class VulnerabilitiesPageComponent implements OnInit {
  private readonly fb = inject(FormBuilder);
  private readonly useCases = inject(VulnerabilityUseCasesService);

  readonly vulnerabilities = signal<Vulnerability[]>([]);
  readonly loading = signal(false);
  readonly saving = signal(false);
  readonly searching = signal(false);
  readonly error = signal<string | null>(null);
  readonly searchError = signal<string | null>(null);
  readonly editingId = signal<number | null>(null);
  readonly searchedCveId = signal<string | null>(null);
  readonly viewingItem = signal<Vulnerability | null>(null);
  private searchResponse = signal<VulnerabilitySearchResponse | null>(null);

  readonly severityOptions: SeverityLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  readonly statusOptions: VulnerabilityStatus[] = ['ACTIVE', 'ARCHIVED'];
  readonly sourceOptions: SourceType[] = ['CISA', 'NUCLEI'];

  readonly total = computed(() => this.vulnerabilities().length);

  readonly form: VulnerabilityForm = this.fb.nonNullable.group({
    cveId: ['', [Validators.required, Validators.maxLength(64)]],
    title: ['', [Validators.required, Validators.maxLength(255)]],
    severity: 'MEDIUM' as SeverityLevel,
    status: 'ACTIVE' as VulnerabilityStatus,
    cvssScore: this.fb.control<number | null>(null, [Validators.min(0), Validators.max(10)]),
    affectedProduct: '',
    affectedVendor: '',
    affectedVersion: '',
    remediation: '',
    sourceTypes: this.fb.nonNullable.control<SourceType[]>(['CISA'], [Validators.required]),
  });

  ngOnInit(): void {
    this.loadVulnerabilities();
  }

  loadVulnerabilities(): void {
    this.loading.set(true);
    this.error.set(null);

    this.useCases
      .getVulnerabilities()
      .pipe(finalize(() => this.loading.set(false)))
      .subscribe({
        next: (items) => this.vulnerabilities.set(items),
        error: () => this.error.set('No se pudo cargar el inventario de vulnerabilidades.'),
      });
  }

  searchVulnerability(): void {
    const cveId = this.form.controls.cveId.value.trim();

    if (!cveId) {
      this.searchError.set('Por favor ingresa un CVE ID');
      return;
    }

    this.searching.set(true);
    this.searchError.set(null);

    this.useCases
      .searchVulnerability(cveId)
      .pipe(finalize(() => this.searching.set(false)))
      .subscribe({
        next: (response) => {
          this.searchedCveId.set(cveId);
          this.searchResponse.set(response);
          this.prefillForm(response);
        },
        error: () => {
          this.searchError.set('No se encontró el CVE en NVD. Verifica el ID e intenta nuevamente.');
          this.searchedCveId.set(null);
          this.searchResponse.set(null);
        },
      });
  }

  private prefillForm(response: VulnerabilitySearchResponse): void {
    const severity = this.mapSeverityFromNvd(response.cvss.severity);

    this.form.patchValue({
      title: response.software || '',
      severity,
      cvssScore: response.cvss.score || null,
      affectedProduct: response.software || '',
      affectedVendor: response.vendor || '',
      affectedVersion: response.affectedVersions || '',
      remediation: response.patchAvailable ? 'Parche disponible' : 'Sin parche disponible',
    });
  }

  private mapSeverityFromNvd(nvdSeverity: string): SeverityLevel {
    const severity = nvdSeverity?.toUpperCase() || 'MEDIUM';
    return this.severityOptions.includes(severity as SeverityLevel)
      ? (severity as SeverityLevel)
      : 'MEDIUM';
  }

  submit(): void {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }

    const cveId = this.form.controls.cveId.value.trim();
    const editId = this.editingId();

    // Validar que el cveId no exista en la DB si es una creación nueva
    if (!editId) {
      const exists = this.vulnerabilities().some((v) => v.cveId === cveId);
      if (exists) {
        this.searchError.set('cveId ya existe');
        return;
      }
    }

    this.saving.set(true);
    this.error.set(null);
    this.searchError.set(null);

    const payload = this.toPayload();
    const request$ = editId
      ? this.useCases.updateVulnerability(editId, payload)
      : this.useCases.createVulnerability(payload);

    request$.pipe(finalize(() => this.saving.set(false))).subscribe({
      next: () => {
        this.resetForm();
        this.loadVulnerabilities();
      },
      error: () => this.error.set('No se pudo guardar la vulnerabilidad.'),
    });
  }

  openDetail(item: Vulnerability): void {
    this.viewingItem.set(item);
  }

  closeDetail(): void {
    this.viewingItem.set(null);
  }

  startEdit(item: Vulnerability): void {
    if (!item.id) {
      return;
    }

    this.editingId.set(item.id);
    this.searchedCveId.set(null);
    this.form.patchValue({
      cveId: item.cveId,
      title: item.title,
      severity: item.severity,
      status: item.status,
      cvssScore: item.cvssScore ?? null,
      affectedProduct: item.affectedProduct ?? '',
      affectedVendor: item.affectedVendor ?? '',
      affectedVersion: item.affectedVersion ?? '',
      remediation: item.remediation ?? '',
      sourceTypes: [...new Set(item.sources.map((source) => source.sourceType))],
    });
  }

  remove(item: Vulnerability): void {
    if (!item.id) {
      return;
    }

    this.useCases.deleteVulnerability(item.id).subscribe({
      next: () => this.loadVulnerabilities(),
      error: () => this.error.set('No se pudo eliminar la vulnerabilidad.'),
    });
  }

  toggleSource(source: SourceType): void {
    const selected = this.form.controls.sourceTypes.value;
    const hasSource = selected.includes(source);
    const next = hasSource ? selected.filter((value) => value !== source) : [...selected, source];

    this.form.controls.sourceTypes.setValue(next.length > 0 ? next : [source]);
  }

  hasSource(item: Vulnerability, type: SourceType): boolean {
    return item.sources.some((source) => source.sourceType === type);
  }

  resetForm(): void {
    this.editingId.set(null);
    this.searchedCveId.set(null);
    this.searchError.set(null);
    this.searchResponse.set(null);
    this.form.reset({
      cveId: '',
      title: '',
      severity: 'MEDIUM',
      status: 'ACTIVE',
      cvssScore: null,
      affectedProduct: '',
      affectedVendor: '',
      affectedVersion: '',
      remediation: '',
      sourceTypes: ['CISA'],
    });
  }

  trackById(_: number, item: Vulnerability): number | string {
    return item.id ?? item.cveId;
  }

  private toPayload(): Vulnerability {
    const value = this.form.getRawValue();
    const nvd = this.searchResponse();

    return {
      cveId: value.cveId.trim(),
      title: value.title.trim(),
      description: nvd?.description || undefined,
      severity: value.severity,
      status: value.status,
      cvssScore: value.cvssScore ?? undefined,
      cvssVector: nvd?.cvss?.vector || undefined,
      affectedProduct: value.affectedProduct.trim() || undefined,
      affectedVendor: value.affectedVendor.trim() || undefined,
      affectedVersion: value.affectedVersion.trim() || undefined,
      remediation: value.remediation.trim() || undefined,
      publishedAt: nvd?.published || undefined,
      sourceUpdatedAt: nvd?.lastModified || undefined,
      sources: value.sourceTypes.map((sourceType) => ({ sourceType })),
    };
  }
}
