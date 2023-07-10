package com.auth.curi.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorType {
    WORKSPACE_NOT_EXISTS("WORKSPACE-001", "존재하지 않는 워크 스페이스입니다."),
    DUPLICATED_WORKSPACE_NAME ("WORKSPACE-002", "중복된 워크 스페이스 이름입니다."),
    USER_NOT_EXISTS ("USER-001", "존재하지 않는 유저입니다."),

    FIREBASE_TOKEN_NULL ("FIREBASE-001", "firebase access token이 null입니다."),

    TOKENS_NOT_VALID ("TOKEN-001", "auth token과 refresh token 모두 유효하지 않습니다."),
    NO_BEARER_AUTH ("TOKEN-002", "auth token은 Bearer로 시작해야 합니다.");

    private final String errorCode;
    private final String message;
}
