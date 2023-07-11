package com.auth.curi.swagger;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
// backend-app-service:8080
// auth-app-service:8000
/**
 * Swagger springdoc-ui 구성 파일
 */
@Configuration
public class SwaggerConfig {

    SecurityScheme auth = new SecurityScheme()
            .type(SecurityScheme.Type.APIKEY).in(SecurityScheme.In.COOKIE).name("refreshToken");
    SecurityRequirement securityRequirement = new SecurityRequirement().addList("basicAuth");

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes("Auth-token",
                                new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT"))
                        .addSecuritySchemes("firebase-access-token",
                                new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")))
                .info(new Info()
                        .title("Curi Auth API")
                        .description("Documentation of Curi Auth API")
                        .version("1.0")
                );

    }
        /*
        Info info = new Info()
                .title("Curi Auth API Document")
                .version("v0.0.1")
                .description("큐리 인증서버의 API 명세서입니다.");
        return new OpenAPI()
                .components(new Components())
                .info(info);
    }

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI().components(new Components().addSecuritySchemes("bearer-key",
                new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")));
    }*/
}