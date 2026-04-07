package com.example.securityservice.dto;

import java.util.List;

public record TokenValidationResponse(
        boolean valid,
        String username,
        List<String> roles,
        String expiresAt
) {
}
