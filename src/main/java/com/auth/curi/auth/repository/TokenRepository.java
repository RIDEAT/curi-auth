package com.auth.curi.auth.repository;

import com.auth.curi.auth.repository.entity.RefreshToken;
import com.auth.curi.auth.repository.entity.Token;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByUserId(String userId);

}
