# Sistema de Gestión de Vulnerabilidades CVE

Aplicación full-stack para registrar, buscar y gestionar vulnerabilidades de seguridad (CVEs) provenientes de fuentes como **CISA** y **Nuclei**, con integración a la API oficial del **NVD (National Vulnerability Database)**.

---


## Stack tecnológico

### Backend (`BackTestBcWithSpringBoot/`)
- **Java 17** + **Spring Boot 3.5**
- **Spring Data JPA** + **Hibernate**
- **PostgreSQL** como base de datos relacional
- **Springdoc OpenAPI** — documentación Swagger automática
- **Lombok** para reducir boilerplate
- Arquitectura en capas: `Domain` → `Application` → `Infrastructure` → `Web`

### Frontend (`FrontendTestBcWithAngular/`)
- **Angular 21**
- **Tailwind CSS v4**
- Arquitectura limpia: `domain` → `application` → `infrastructure` → `ui`

---

## Funcionalidades

- **Listado de CVEs** registrados en la base de datos
- **Crear** un CVE manualmente o llenando el formulario desde la búsqueda en NVD
- **Buscar en NVD** por ID de CVE (ej. `CVE-2021-44228`) para autocompletar datos: descripción, score CVSS, vector, fechas y versiones afectadas
- **Editar** y **eliminar** registros existentes
- **Ver detalle** completo de una vulnerabilidad en un modal


---

## API REST

Base URL: `http://localhost:8080/api/v1`

`GET` | `/vulnerabilities` | Listar todos los CVEs |
`GET` | `/vulnerabilities/{id}` | Obtener un CVE por ID interno |
`POST` | `/vulnerabilities` | Crear un nuevo CVE |
`PUT` | `/vulnerabilities/{id}` | Actualizar un CVE |
`DELETE` | `/vulnerabilities/{id}` | Eliminar un CVE |
`GET` | `/vulnerabilities/search?cveId=CVE-XXXX-XXXXX` | Buscar en NVD por CVE ID |

Documentación interactiva Swagger UI: **http://localhost:8080/swagger-ui/index.html**



## Cómo levantar el sistema

```bash
# Desde la raíz del proyecto (donde está docker-compose.yml)
docker compose up --build -d
```

**Acceder a la aplicación**

| URL | Descripción |
|---|---|
| http://localhost:4200 | Aplicación web |
| http://localhost:8080/swagger-ui/index.html | API docs Swagger |
| http://localhost:8080/api/v1/vulnerabilities | Endpoint REST directo |

---

### Reconstruir todo desde cero

```bash
# Detener y eliminar contenedores
docker compose down

# Levantar todo nuevamente
docker compose up --build -d
```

---

## Detener el sistema

```bash
docker compose down
```

