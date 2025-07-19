package com.pickfolio.auth.domain.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode
public class RefreshRequest {
    @NotBlank(message = "Refresh token cannot be blank")
    private String refreshToken;
    @NotBlank(message = "Device info cannot be blank")
    private String deviceInfo;
}
