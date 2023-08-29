package com.auth.curi.security.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Schema(description = "템플릿 관련 VO")

public class TokenDto {
    @Schema(description = "auth token")
    private String authToken;
    @Schema(description = "refresh token")
    private String refreshToken;
    @Schema(description = "user Email")
    private String userEmail;


    public TokenDto(String authToken, String refreshToken, String userEmail){
        this.authToken = authToken;
        this.refreshToken = refreshToken;
        this.userEmail = userEmail;
    }
}
