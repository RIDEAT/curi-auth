package com.auth.curi.auth.repository.entity;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;

@Getter
@Setter
@Entity
@NoArgsConstructor
@Table(name = "jwt_token")
public class Token {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String authToken;
    @NotBlank
    private String refreshToken;
    @NotBlank
    private String userId;

    @Builder
    public Token(String authToken, String refreshToken, String userId) {
        this.authToken = authToken;
        this.refreshToken = refreshToken;
        this.userId = userId;
    }

}
