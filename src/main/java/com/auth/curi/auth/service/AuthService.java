package com.auth.curi.auth.service;

import com.auth.curi.auth.repository.RefreshTokenRepository;
import com.auth.curi.auth.repository.TokenRepository;
import com.auth.curi.auth.repository.entity.RefreshToken;
import com.auth.curi.auth.repository.entity.Token;
import com.auth.curi.exception.CuriException;
import com.auth.curi.exception.ErrorType;
import com.auth.curi.security.dto.TokenDto;
import com.auth.curi.security.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class AuthService {
    @Value("${jwt.authSecretKey}")
    private String authSecretKey;

    @Value("${jwt.refreshSecretKey}")
    private String refreshSecretKey;

    @Value("${jwt.authExpiredMs}")
    private Long authExpiredMs;

    @Value("${jwt.refreshExpiredMs}")
    private Long refreshExpiredMs;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenRepository tokenRepository;

    public TokenDto authorize(String userEmail) {
        log.info("userEmail : {}", userEmail);

        String authJWT = JwtUtil.createJWT(userEmail, authSecretKey, authExpiredMs);
        String refreshJWT = JwtUtil.createJWT(userEmail, refreshSecretKey, refreshExpiredMs);

        log.info("userEmail : {} 가 만든 refreshJWT : {}", userEmail, refreshJWT);

        Optional<Token> token = tokenRepository.findByUserEmail(userEmail);
        if (token.isPresent()){
            token.get().setAuthToken(authJWT);
            token.get().setRefreshToken(refreshJWT);
            tokenRepository.save(token.get());
        } else{
            Token newToken = Token.builder().authToken(authJWT).refreshToken(refreshJWT).userEmail(userEmail).build();
            tokenRepository.save(newToken);
        }

        /*
        //refresh 토큰이 있는지 확인
        Optional<RefreshToken> refreshToken = refreshTokenRepository.findByUserId(userId);


        // 있다면 새토큰 발급후 업데이트
        // 없다면 새로 만들고 디비 저장
        if (refreshToken.isPresent()) {
            refreshTokenRepository.save(refreshToken.get().updateToken(refreshJWT));
        } else {
            RefreshToken newToken = new RefreshToken(refreshJWT, userId);
            refreshTokenRepository.save(newToken);
        }*/

        return new TokenDto(authJWT, refreshJWT, userEmail);
    }


    public TokenDto verify(String authToken, String refreshToken) {

        if (JwtUtil.isValid(authToken, authSecretKey)) {
            log.info("auth token이 유효합니다.");
            String userId = JwtUtil.getUserEmail(authToken, authSecretKey);
            return new TokenDto(authToken, refreshToken, userId);
        }

        log.info("auth token이 유효하지 않습니다. : {}", authToken);

        if (!JwtUtil.isValid(refreshToken, refreshSecretKey)) {
            log.info("refresh token 이 유효하지 않습니다.");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        String userId = JwtUtil.getUserEmail(refreshToken, refreshSecretKey);
        Optional<Token> tokenInDB = tokenRepository.findByUserEmail(userId);
        if (!tokenInDB.isPresent()){
            log.info("등록된 refresh token이 없습니다. ");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        if (!tokenInDB.get().getRefreshToken().equals(refreshToken)){
            log.info("등록된 refresh token과 현재 refresh token이 다릅니다.");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        log.info("refresh token은 유효합니다. : {}", refreshToken);
        log.info("auth token을 발급합니다.");
        String newAuthToken = JwtUtil.createJWT(userId, authSecretKey, authExpiredMs);

        tokenInDB.get().setAuthToken(newAuthToken);
        tokenRepository.save(tokenInDB.get());

        /*

        // refresh 토큰이 이미 있는 놈이지도 확인해야함 디비에서
        Optional<RefreshToken> refreshTokenInDB = refreshTokenRepository.findByUserId(userId);

        if (!refreshTokenInDB.isPresent()){
            log.info("등록된 refresh token이 없습니다. ");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        if (!refreshTokenInDB.get().getRefreshToken().equals(refreshToken)){
            log.info("등록된 refresh token과 현재 refresh token이 다릅니다.");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        log.info("refresh token은 유효합니다. : {}", refreshToken);
        log.info("auth token을 발급합니다.");
        String newAuthToken = JwtUtil.createJWT(userId, authSecretKey, authExpiredMs);

         */

        return new TokenDto(newAuthToken, refreshToken, userId);
    }

    public void deleteToken(String authToken){

        /*
        if (!JwtUtil.isValid(refreshToken, refreshSecretKey)) {
            log.info("refresh token 이 유효하지 않습니다.");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        String userId = JwtUtil.getUserId(refreshToken, refreshSecretKey);
        Optional<RefreshToken> refreshTokenInDB = refreshTokenRepository.findByUserId(userId);

        if (!refreshTokenInDB.isPresent()){
            log.info("등록된 refresh token이 없습니다. ");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        if (!refreshTokenInDB.get().getRefreshToken().equals(refreshToken)){
            log.info("등록된 refresh token과 현재 refresh token이 다릅니다.");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }
*/

        String userEmail = JwtUtil.getUserEmail(authToken, authSecretKey);
        Optional<Token> tokenInDB = tokenRepository.findByUserEmail(userEmail);
        if (!tokenInDB.isPresent()){
            log.info("등록된 token이 없습니다.");
            throw new CuriException(HttpStatus.UNAUTHORIZED, ErrorType.TOKENS_NOT_VALID);
        }

        tokenRepository.delete(tokenInDB.get());
        log.info("등록된 refresh token을 지웠습니다.");
        //  refreshTokenRepository.delete(refreshTokenInDB.get());

    }
}
