package com.test.bc.Infrastructure.Config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

@Configuration
public class JacksonConfig {

    private static final DateTimeFormatter LENIENT_OFFSET = new DateTimeFormatterBuilder()
            .append(DateTimeFormatter.ISO_LOCAL_DATE_TIME)
            .optionalStart()
            .appendOffsetId()
            .optionalEnd()
            .toFormatter();

    @Bean
    public Jackson2ObjectMapperBuilder jacksonBuilder() {
        SimpleModule lenientDateModule = new SimpleModule();
        lenientDateModule.addDeserializer(OffsetDateTime.class, new StdDeserializer<>(OffsetDateTime.class) {
            @Override
            public OffsetDateTime deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
                String raw = p.getText().trim();
                if (raw.isEmpty()) return null;
                try {
                    return OffsetDateTime.parse(raw, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
                } catch (Exception ignored) {
                    LocalDateTime local = LocalDateTime.parse(raw, DateTimeFormatter.ISO_LOCAL_DATE_TIME);
                    return local.atOffset(ZoneOffset.UTC);
                }
            }
        });

        return new Jackson2ObjectMapperBuilder()
                .modules(new JavaTimeModule(), lenientDateModule)
                .featuresToDisable(
                        com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS
                );
    }
}
