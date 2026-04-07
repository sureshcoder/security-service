package com.example.securityservice.controller;

import com.example.securityservice.dto.AuthRequest;
import com.example.securityservice.dto.AuthResponse;
import com.example.securityservice.dto.LogoutRequest;
import com.example.securityservice.dto.RefreshTokenRequest;
import com.example.securityservice.dto.RegisterRequest;
import com.example.securityservice.dto.TokenValidationRequest;
import com.example.securityservice.dto.TokenValidationResponse;
import com.example.securityservice.entity.RefreshToken;
import com.example.securityservice.entity.User;
import com.example.securityservice.repository.UserRepository;
import com.example.securityservice.security.JwtUtil;
import com.example.securityservice.service.RefreshTokenService;
import com.example.securityservice.service.TokenBlacklistService;
import com.example.securityservice.service.UserService;
import io.jsonwebtoken.Claims;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = jwtUtil.generateToken(userDetails);

        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userDetails.getUsername()));
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return ResponseEntity.ok(new AuthResponse(token, refreshToken.getToken(), userDetails.getUsername(), roles));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenService.findByToken(request.refreshToken());
        refreshTokenService.verifyExpiration(refreshToken);

        User user = refreshToken.getUser();
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String newJwt = jwtUtil.generateToken(userDetails);

        RefreshToken newRefreshToken = refreshTokenService.rotateRefreshToken(refreshToken);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return ResponseEntity.ok(new AuthResponse(newJwt, newRefreshToken.getToken(), user.getUsername(), roles));
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody RegisterRequest request) {
        User user = userService.registerUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "User registered successfully", "username", user.getUsername()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@Valid @RequestBody LogoutRequest request) {
        if (!jwtUtil.validateToken(request.token())) {
            return ResponseEntity.ok(Map.of("message", "Token is already invalid"));
        }

        Claims claims = jwtUtil.getAllClaims(request.token());
        long ttlMillis = claims.getExpiration().getTime() - Instant.now().toEpochMilli();
        if (ttlMillis > 0) {
            tokenBlacklistService.blacklist(request.token(), Duration.ofMillis(ttlMillis));
        }

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validateToken(@Valid @RequestBody TokenValidationRequest request) {
        if (!jwtUtil.validateToken(request.token()) || tokenBlacklistService.isBlacklisted(request.token())) {
            return ResponseEntity.ok(new TokenValidationResponse(false, null, null, null));
        }

        Claims claims = jwtUtil.getAllClaims(request.token());
        String username = claims.getSubject();
        List<String> roles = claims.get("roles", List.class);
        String expiresAt = claims.getExpiration().toInstant().toString();

        return ResponseEntity.ok(new TokenValidationResponse(true, username, roles, expiresAt));
    }
}
