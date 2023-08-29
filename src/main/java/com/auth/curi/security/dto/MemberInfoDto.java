package com.auth.curi.security.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class MemberInfoDto {
    private String sub;
    private String email;

    @Builder
    public MemberInfoDto(String sub, String email) {
        this.sub = sub;
        this.email = email;
    }
}
