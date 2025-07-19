package com.pickfolio.auth.domain.response;

import lombok.*;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
public class LoginResponse {
    private final String accessToken;
    private final String refreshToken;
}
