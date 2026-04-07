package com.example.securityservice.dto;

import java.util.List;

public record AuthResponse(
        String token,
        String type,
        String refreshToken,
        String username,
        List<String> roles
) {
    public AuthResponse(String token, String refreshToken, String username, List<String> roles) {
        this(token, "Bearer", refreshToken, username, roles);
    }
}
