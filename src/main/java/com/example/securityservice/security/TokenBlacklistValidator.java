package com.example.securityservice.security;

import com.example.securityservice.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenBlacklistValidator implements OAuth2TokenValidator<Jwt> {

    private final TokenBlacklistService tokenBlacklistService;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        if (tokenBlacklistService.isBlacklisted(jwt.getTokenValue())) {
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Token has been blacklisted", null));
        }
        return OAuth2TokenValidatorResult.success();
    }
}
