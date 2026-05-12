# Script de Análisis de Vulnerabilidades

Este script en Python descarga, enriquece y analiza vulnerabilidades conocidas desde múltiples fuentes públicas (CISA KEV, Nuclei Templates y NIST NVD API).

## ¿Qué hace?

1. **Descarga vulnerabilidades de CISA KEV**  
   Consume el feed público de la Agencia de Ciberseguridad de EE.UU. con vulnerabilidades explotadas activamente.

2. **Descarga vulnerabilidades de Nuclei Templates**  
   Obtiene el listado de CVEs cubiertos por las plantillas de Nuclei

3. **Enriquece con datos de NIST NVD API**  
   Para las primeras 10 vulnerabilidades de cada fuente, consulta la API de NIST para obtener:
   - Descripción detallada
   - Puntuación CVSS v3.1 y v2
   - Severidad y vector de ataque
   - Exploitability Score / Impact Score
   - CWEs (tipos de debilidad)
   - CPEs (productos afectados)
   - Fechas de publicación y última modificación

4. **Genera un análisis de tendencias**  
   Produce reportes estadísticos para CISA KEV, Nuclei y el conjunto combinado:
   - Distribución por mes de publicación
   - Meses con picos de actividad
   - Top CWEs y CPEs más frecuentes

## Requisitos

- [Docker] instalado y corriendo

## Cómo correrlo con Docker

### 1. Construir la imagen

```bash
docker build -t script-python .
```

### 2. Ejecutar y guardar el output en un archivo

```powershell
docker run --rm script-python 2>&1 | Tee-Object -FilePath "output.txt"
```

El archivo `output.txt` quedará en el directorio donde se ejecutó el comando con el resultado completo del análisis.

### Solo ver el output en terminal

```bash
docker run --rm script-python
```