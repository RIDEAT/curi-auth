package com.auth.curi.security.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class TokenDto {
    private String authToken;
    private String refreshToken;
    private String userId;


    public TokenDto(String authToken, String refreshToken, String userId){
        this.authToken = authToken;
        this.refreshToken = refreshToken;
        this.userId = userId;
    }
}
