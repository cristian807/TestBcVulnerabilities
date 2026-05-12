import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';

import { routes } from './app.routes';
import { provideClientHydration, withEventReplay } from '@angular/platform-browser';
import { VulnerabilityRepository } from './domain/repositories/vulnerability.repository';
import { VulnerabilityHttpRepository } from './infrastructure/http/vulnerability-http.repository';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes),
    provideHttpClient(),
    provideClientHydration(withEventReplay()),
    { provide: VulnerabilityRepository, useClass: VulnerabilityHttpRepository }
  ]
};
