package com.example.securityservice.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenValidationRequest(
        @NotBlank(message = "Token must not be blank")
        String token
) {
}
