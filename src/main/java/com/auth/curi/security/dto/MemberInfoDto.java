package com.auth.curi.security.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class MemberInfoDto {
    private String name;
    private String sub;
    private String email;

    @Builder
    public MemberInfoDto(String name, String sub, String email) {
        this.name = name;
        this.sub = sub;
        this.email = email;
    }
}
