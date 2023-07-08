package com.auth.curi.auth.controller;


import com.auth.curi.auth.service.AuthService;
import com.auth.curi.exception.CuriException;
import com.auth.curi.exception.ErrorType;
import com.auth.curi.firebase.FirebaseAuthentication;
import com.auth.curi.security.dto.TokenDto;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.FirebaseToken;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

@Controller
@Slf4j
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // firebase access token 이 valid 하면, auth 토큰과 refresh 토큰 발급
    @GetMapping("/authorize")
    public ResponseEntity authorize(HttpServletRequest request, HttpServletResponse response){
        try {
            String accessToken = request.getHeader("Authentication");
            log.info("accessToken: {}", accessToken);
            // Access Token 검증
            FirebaseToken decodedToken = FirebaseAuthentication.verifyAccessToken(accessToken);

            // 유효한 Access Token으로부터 사용자 정보 가져오기
            String userId = decodedToken.getUid();
            String userEmail =decodedToken.getEmail();

            TokenDto tokenDto = authService.authorize(userId);


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
            responseBody.put("userId", userId);
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
            String userId = tokenDto.getUserId();
            responseBody.put("userId", userId);

            return new ResponseEntity(responseBody, HttpStatus.ACCEPTED);


        } catch (CuriException e){
            log.info(e.getMessage());
            Map<String, Object> errorBody= new HashMap<>();
            errorBody.put("error", e.getMessage());

            return new ResponseEntity(errorBody, e.getHttpStatus());
        }
    }




    @GetMapping("/logout")
    public ResponseEntity logout (HttpServletRequest request, HttpServletResponse response) {

        try {
            TokenDto tokenFromRequest = getTokenDto(request);
            // Token 꺼내기
            String refreshToken = tokenFromRequest.getRefreshToken();
            authService.deleteRefreshToken(refreshToken);

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


    @GetMapping("/test")
    public ResponseEntity returnTest(){
        String responseBody = "test";
        return ResponseEntity.ok(responseBody);
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
                if(cookie.getName().equals(name)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}