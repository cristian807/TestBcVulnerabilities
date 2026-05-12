# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jdk-jammy AS build
WORKDIR /app

# Copiar wrapper y configuración de Gradle primero (capa cacheada)
COPY gradlew gradlew.bat settings.gradle build.gradle ./
COPY gradle ./gradle

# Descargar dependencias sin compilar (mejora cache de capas)
RUN chmod +x gradlew && ./gradlew dependencies --no-daemon -q || true

# Copiar el código fuente y compilar el JAR
COPY src ./src
RUN ./gradlew bootJar --no-daemon -x test

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

