package com.auth.curi.auth.controller;


import com.auth.curi.auth.service.AuthService;
import com.auth.curi.exception.CuriException;
import com.auth.curi.exception.ErrorType;
import com.auth.curi.firebase.FirebaseAuthentication;
import com.auth.curi.security.dto.GoogleOAuthResponseDto;
import com.auth.curi.security.dto.MemberInfoDto;
import com.auth.curi.security.dto.TokenDto;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import io.jsonwebtoken.impl.Base64UrlCodec;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@RestController
@Slf4j
@RequiredArgsConstructor
@Tag(name = "Auth Server", description = "Curi-Auth API Document")
public class AuthController {

    private final AuthService authService;

    private final String GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
    @Value("${oauth2.client.google.client-id}")
    private String GOOGLE_CLIENT_ID;
    @Value("${oauth2.client.google.client-secret}")
    private String GOOGLE_CLIENT_SECRET;
    @Value("${oauth2.client.google.redirect-uri}")
    private String GOOGLE_CLIENT_REDIRECT_URI;
    @GetMapping("/authorize/google")
    public ResponseEntity authorizeGoogle(@RequestParam("code") String accessCode, HttpServletResponse response){

        RestTemplate restTemplate = new RestTemplate();
        Map<String, String> params = new HashMap<>();

        params.put("code", accessCode);
        params.put("client_id", GOOGLE_CLIENT_ID);
        params.put("client_secret", GOOGLE_CLIENT_SECRET);
        params.put("redirect_uri", GOOGLE_CLIENT_REDIRECT_URI);
        params.put("grant_type", "authorization_code");

        ResponseEntity<GoogleOAuthResponseDto> responseEntity = restTemplate.postForEntity(GOOGLE_TOKEN_URL, params, GoogleOAuthResponseDto.class);
        if(responseEntity.getStatusCode() == HttpStatus.OK)
        {
            var decoded = decryptBase64UrlToken(responseEntity.getBody().getId_token().split("\\.")[1]);

            ObjectMapper mapper = new ObjectMapper()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            MemberInfoDto member = new MemberInfoDto();
            try {
                member = mapper.readValue(decoded, MemberInfoDto.class);
            }catch (Exception e){
                log.info(e.getMessage());
            }

            var userEmail = member.getEmail();
            TokenDto tokenDto = authService.authorize(userEmail);

            //userService.dbStore(userId, userEmail);
            //이 부분은 user sever에서 auth server 로 물어볼때. 알려주자 .

            // Put JWT in header
            HttpHeaders headers = new HttpHeaders();
            headers.set("AuthToken", tokenDto.getAuthToken());

            Cookie cookie = new Cookie("refreshToken", tokenDto.getRefreshToken());
            //cookie.setMaxAge(refreshExpiredMs.intValue()/1000);
            log.info("Cookie 에 담은 refreshToken: {}", tokenDto.getRefreshToken());
            // cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);

            Map<String, Object> responseBody= new HashMap<>();
            responseBody.put("userEmail", userEmail);


            return new ResponseEntity(responseBody, headers, HttpStatus.ACCEPTED);
        }

        return null;
    }
    // firebase access token 이 valid 하면, auth 토큰과 refresh 토큰 발급
    @GetMapping("/authorize/firebase")
    @Operation(summary = "firebase access token 이 valid 하면, auth 토큰과 refresh 토큰 발급")
    @SecurityRequirement(name = "firebase-access-token")
    public ResponseEntity authorize(HttpServletRequest request, HttpServletResponse response){
        try {
            String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                log.error("authorization 은 Bearer로 시작해야 합니다. ", authorization);
                throw new CuriException(HttpStatus.BAD_REQUEST, ErrorType.NO_BEARER_AUTH);
            }

            String accessToken = authorization.split(" ")[1];

            log.info("accessToken: {}", accessToken);
            // Access Token 검증
            FirebaseToken decodedToken = FirebaseAuthentication.verifyAccessToken(accessToken);

            // 유효한 Access Token으로부터 사용자 정보 가져오기
            String userEmail =decodedToken.getEmail();

            TokenDto tokenDto = authService.authorize(userEmail);


            //userService.dbStore(userId, userEmail);
            //이 부분은 user sever에서 auth server 로 물어볼때. 알려주자 .

            // Put JWT in header
            HttpHeaders headers = new HttpHeaders();
            headers.set("AuthToken", tokenDto.getAuthToken());

            Cookie cookie = new Cookie("refreshToken", tokenDto.getRefreshToken());
            //cookie.setMaxAge(refreshExpiredMs.intValue()/1000);
            log.info("Cookie 에 담은 refreshToken: {}", tokenDto.getRefreshToken());
            // cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);

            Map<String, Object> responseBody= new HashMap<>();
            responseBody.put("userEmail", userEmail);


            return new ResponseEntity(responseBody, headers, HttpStatus.ACCEPTED);
        } catch (FirebaseAuthException e) {
            log.info("FirebaseAuthException");
            Map<String, Object> errorBody= new HashMap<>();
            errorBody.put("error", "Firebase access token이 유효하지 않습니다.");

            // Access Token이 유효하지 않은 경우 또는 검증에 실패한 경우 에러 처리
            return new ResponseEntity(errorBody, HttpStatus.NOT_ACCEPTABLE);


        } catch(CuriException e){

            log.info(e.getMessage());
            Map<String, Object> errorBody= new HashMap<>();
            errorBody.put("error", e.getMessage());

            return new ResponseEntity(errorBody, e.getHttpStatus());
        }
    }

    // auth 토큰과 refresh 토큰을 받고 verify한다.
    // auth 토큰이 맞는 경우, 통과
    // auth 토큰이 틀리고 refresh 토큰이 맞는 경우, 통과 (새 auth 토큰 발급)
    // auth 토큰이 틀리고 refresh 토큰이 틀린 경우, 실패

    @GetMapping("/verify")
    @Operation(
            summary = "auth와 refresh 토큰을 검증합니다. ",
            parameters = {
                    @Parameter(
                            name = "refreshToken",
                            in = ParameterIn.COOKIE,
                            schema = @Schema(implementation = String.class)
                    )
            }
    )
    @SecurityRequirement(name = "Auth-token")
    public ResponseEntity verify(HttpServletRequest request, HttpServletResponse response) {
        try {
            TokenDto tokenFromRequest = getTokenDto(request);

            // Token 꺼내기
            String authToken = tokenFromRequest.getAuthToken();
            String refreshToken = tokenFromRequest.getRefreshToken();

            TokenDto tokenDto = authService.verify(authToken, refreshToken);
            response.setHeader("AuthToken", tokenDto.getAuthToken());

            Cookie cookie = new Cookie("refreshToken", tokenDto.getRefreshToken());
//          cookie.setMaxAge(refreshExpiredMs.intValue()/1000);
            log.info("Cookie 에 담은 refreshToken: {}", tokenDto.getRefreshToken());
            // cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            response.addCookie(cookie);

            Map<String, Object> responseBody= new HashMap<>();
            String userEmail = tokenDto.getUserEmail();
            responseBody.put("userEmail", userEmail);

            return new ResponseEntity(responseBody, HttpStatus.ACCEPTED);


        } catch (CuriException e){
            log.info(e.getMessage());
            Map<String, Object> errorBody= new HashMap<>();
            errorBody.put("error", e.getMessage());

            return new ResponseEntity(errorBody, e.getHttpStatus());
        }
    }




    @GetMapping("/logout")
    @Operation(summary = "로그아웃", description = "유저의 refresh token을 지웁니다.",
            parameters = {
            @Parameter(
                    name = "refreshToken",
                    in = ParameterIn.COOKIE,
                    schema = @Schema(implementation = String.class)
            )
    })
    @SecurityRequirement(name = "Auth-token")
    public ResponseEntity logout (HttpServletRequest request, HttpServletResponse response) {

        try {
            TokenDto tokenFromRequest = getTokenDto(request);

            // Token 꺼내기
            String authToken = tokenFromRequest.getAuthToken();
            //String refreshToken = tokenFromRequest.getRefreshToken();
            authService.deleteToken(authToken);

            Map<String, Object> responseBody= new HashMap<>();
            responseBody.put("message", "성공적으로 logout 되었습니다.");
            return new ResponseEntity(responseBody, HttpStatus.ACCEPTED);

        } catch(CuriException e){
            log.info(e.getMessage());
            Map<String, Object> errorBody= new HashMap<>();
            errorBody.put("error", e.getMessage());

            return new ResponseEntity(errorBody, e.getHttpStatus());
        }
    }

    private static TokenDto getTokenDto(HttpServletRequest request){
        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        log.info("authorization: {}", authorization);

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.error("authorization 은 Bearer로 시작해야 합니다. ", authorization);
            throw new CuriException(HttpStatus.BAD_REQUEST, ErrorType.NO_BEARER_AUTH);
        }

        // Token 꺼내기
        String authToken = authorization.split(" ")[1];
        String refreshToken = getCookieName(request, "refreshToken");
        TokenDto tokenDto = new TokenDto();
        tokenDto.setAuthToken(authToken);
        tokenDto.setRefreshToken(refreshToken);

        return tokenDto;
    }

    private static String getCookieName(HttpServletRequest req,String name) {
        Cookie[] cookies = req.getCookies();
        if(cookies!=null) {
            for (Cookie cookie : cookies) {
                log.info(cookie.getName());
                if(cookie.getName().equals(name)) {
                    return cookie.getValue();
                }
            }
        }
        else log.info("cookie is null");
        return null;
    }

    private String decryptBase64UrlToken(String jwtToken){
        byte[] decode = new Base64UrlCodec().decode(jwtToken);
        return new String(decode, StandardCharsets.UTF_8);
    }
}