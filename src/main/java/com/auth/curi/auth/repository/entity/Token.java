package com.auth.curi.auth.repository.entity;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.validation.constraints.NotBlank;

@Getter
@Setter
@Entity
@NoArgsConstructor
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
