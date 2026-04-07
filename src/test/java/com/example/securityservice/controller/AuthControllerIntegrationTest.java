package com.example.securityservice.controller;

import com.example.securityservice.entity.RefreshToken;
import com.example.securityservice.entity.User;
import com.example.securityservice.repository.RefreshTokenRepository;
import com.example.securityservice.repository.UserRepository;
import com.example.securityservice.security.JwtUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    // -------------------------------------------------------------------------
    // Register
    // -------------------------------------------------------------------------

    @Test
    void register_withValidData_returns201() throws Exception {
        Map<String, String> body = Map.of(
                "username", "john",
                "email", "john@example.com",
                "password", "secret123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User registered successfully"))
                .andExpect(jsonPath("$.username").value("john"));
    }

    @Test
    void register_withFirstNameAndLastName_returns201() throws Exception {
        Map<String, String> body = Map.of(
                "username", "jane",
                "email", "jane@example.com",
                "password", "secret123",
                "firstName", "Jane",
                "lastName", "Doe"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("jane"));
    }

    @Test
    void register_withDuplicateUsername_returns409() throws Exception {
        Map<String, String> body = Map.of(
                "username", "dupuser",
                "email", "dup@example.com",
                "password", "secret123"
        );
        String json = objectMapper.writeValueAsString(body);

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated());

        Map<String, String> duplicate = Map.of(
                "username", "dupuser",
                "email", "other@example.com",
                "password", "secret123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(duplicate)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Username already exists: dupuser"));
    }

    @Test
    void register_withDuplicateEmail_returns409() throws Exception {
        Map<String, String> first = Map.of(
                "username", "user1",
                "email", "shared@example.com",
                "password", "secret123"
        );
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(first)))
                .andExpect(status().isCreated());

        Map<String, String> second = Map.of(
                "username", "user2",
                "email", "shared@example.com",
                "password", "secret123"
        );
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(second)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists: shared@example.com"));
    }

    @Test
    void register_withBlankUsername_returns400() throws Exception {
        Map<String, String> body = Map.of(
                "username", "",
                "email", "test@example.com",
                "password", "secret123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.username").exists());
    }

    @Test
    void register_withInvalidEmail_returns400() throws Exception {
        Map<String, String> body = Map.of(
                "username", "testuser",
                "email", "not-an-email",
                "password", "secret123"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.email").exists());
    }

    @Test
    void register_withShortPassword_returns400() throws Exception {
        Map<String, String> body = Map.of(
                "username", "testuser",
                "email", "test@example.com",
                "password", "short"
        );

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").exists());
    }

    // -------------------------------------------------------------------------
    // Password hashing (BCrypt)
    // -------------------------------------------------------------------------

    @Test
    void register_storesPasswordAsBcryptHash() throws Exception {
        registerUser("hashuser", "hash@example.com", "plaintext123");

        String storedPassword = userRepository.findByUsername("hashuser")
                .orElseThrow().getPassword();

        // Stored value must be a BCrypt hash, not the plain-text password
        org.junit.jupiter.api.Assertions.assertNotEquals("plaintext123", storedPassword);
        org.junit.jupiter.api.Assertions.assertTrue(
                storedPassword.startsWith("$2a$") || storedPassword.startsWith("$2b$"),
                "Stored password must be a BCrypt hash");
    }

    @Test
    void register_bcryptHashMatchesOriginalPassword() throws Exception {
        registerUser("matchuser", "match@example.com", "mypassword99");

        String storedPassword = userRepository.findByUsername("matchuser")
                .orElseThrow().getPassword();

        // PasswordEncoder.matches() must verify the plain-text against the stored hash
        org.junit.jupiter.api.Assertions.assertTrue(
                passwordEncoder.matches("mypassword99", storedPassword),
                "BCrypt hash must match the original plain-text password");
    }

    @Test
    void login_succeedsOnlyWhenPasswordMatchesBcryptHash() throws Exception {
        registerUser("bcryptlogin", "bcryptlogin@example.com", "correct999");

        // Correct password → login succeeds (BCrypt verification passes)
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", "bcryptlogin", "password", "correct999"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty());

        // Wrong password → login fails (BCrypt mismatch)
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("username", "bcryptlogin", "password", "wrong999"))))
                .andExpect(status().isUnauthorized());
    }

    // -------------------------------------------------------------------------
    // Login
    // -------------------------------------------------------------------------

    @Test
    void login_withValidCredentials_returns200WithTokens() throws Exception {
        registerUser("loginuser", "login@example.com", "password123");

        Map<String, String> loginBody = Map.of(
                "username", "loginuser",
                "password", "password123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.username").value("loginuser"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    void login_withWrongPassword_returns401() throws Exception {
        registerUser("wrongpassuser", "wrongpass@example.com", "correct123");

        Map<String, String> loginBody = Map.of(
                "username", "wrongpassuser",
                "password", "wrongpass"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginBody)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_withNonExistentUser_returns401() throws Exception {
        Map<String, String> loginBody = Map.of(
                "username", "ghost",
                "password", "password123"
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginBody)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_withBlankCredentials_returns400() throws Exception {
        Map<String, String> loginBody = Map.of(
                "username", "",
                "password", ""
        );

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginBody)))
                .andExpect(status().isBadRequest());
    }

    // -------------------------------------------------------------------------
    // Refresh Token
    // -------------------------------------------------------------------------

    @Test
    void refresh_withValidToken_returns200WithNewTokens() throws Exception {
        registerUser("refreshuser", "refresh@example.com", "password123");
        String refreshToken = loginAndGetRefreshToken("refreshuser", "password123");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.type").value("Bearer"))
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.username").value("refreshuser"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    void refresh_rotatesToken_oldTokenIsInvalidated() throws Exception {
        registerUser("rotateuser", "rotate@example.com", "password123");
        String originalRefreshToken = loginAndGetRefreshToken("rotateuser", "password123");

        // First refresh succeeds and issues a new refresh token
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", originalRefreshToken))))
                .andExpect(status().isOk());

        // Using the original (now-rotated) token must fail
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", originalRefreshToken))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid refresh token."));
    }

    @Test
    void refresh_withUnknownToken_returns401() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", UUID.randomUUID().toString()))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid refresh token."));
    }

    @Test
    void refresh_withExpiredToken_returns401() throws Exception {
        registerUser("expiredrefresh", "expiredrefresh@example.com", "password123");
        User user = userRepository.findByUsername("expiredrefresh").orElseThrow();

        RefreshToken expired = RefreshToken.builder()
                .token(UUID.randomUUID().toString())
                .user(user)
                .expiryDate(Instant.now().minusSeconds(3600))
                .build();
        refreshTokenRepository.save(expired);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", expired.getToken()))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Refresh token has expired. Please log in again."));
    }

    @Test
    void refresh_withBlankToken_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", ""))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.refreshToken").exists());
    }

    // -------------------------------------------------------------------------
    // Validate Token
    // -------------------------------------------------------------------------

    @Test
    void validate_withValidToken_returns200WithTokenInfo() throws Exception {
        registerUser("validateuser", "validate@example.com", "password123");
        String token = loginAndGetToken("validateuser", "password123");

        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", token))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.username").value("validateuser"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"))
                .andExpect(jsonPath("$.expiresAt").isNotEmpty());
    }

    @Test
    void validate_withMalformedToken_returns200WithValidFalse() throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", "not.a.valid.jwt"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.username").doesNotExist())
                .andExpect(jsonPath("$.roles").doesNotExist());
    }

    @Test
    void validate_withExpiredToken_returns200WithValidFalse() throws Exception {
        String expiredToken = buildExpiredToken("expireduser");

        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", expiredToken))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void validate_withWrongSignatureToken_returns200WithValidFalse() throws Exception {
        // Token signed with a different key
        String wrongKeyToken = Jwts.builder()
                .subject("someuser")
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600_000L))
                .signWith(io.jsonwebtoken.security.Keys.hmacShaKeyFor(
                        io.jsonwebtoken.io.Decoders.BASE64.decode(
                                "d3Jvbmctc2VjcmV0LWtleS10aGF0LWlzLWxvbmctZW5vdWdoLWZvci1IUzI1Ng==")))
                .compact();

        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", wrongKeyToken))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void validate_withBlankToken_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", ""))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.token").exists());
    }

    // -------------------------------------------------------------------------
    // Logout
    // -------------------------------------------------------------------------

    @Test
    void logout_withValidToken_returns200AndBlacklistsToken() throws Exception {
        registerUser("logoutuser", "logout@example.com", "password123");
        String token = loginAndGetToken("logoutuser", "password123");

        // Token is valid before logout
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", token))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        // Logout
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", token))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));

        // Token is now invalid (blacklisted)
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", token))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    @Test
    void logout_withInvalidToken_returns200WithAlreadyInvalidMessage() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", "not.a.valid.jwt"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Token is already invalid"));
    }

    @Test
    void logout_withBlankToken_returns400() throws Exception {
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", ""))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.token").exists());
    }

    @Test
    void logout_tokenIsRejectedByOAuth2ResourceServer() throws Exception {
        registerUser("logoutrsc", "logoutrsc@example.com", "password123");
        String token = loginAndGetToken("logoutrsc", "password123");

        // Logout the token
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", token))))
                .andExpect(status().isOk());

        // Using the blacklisted token as a Bearer token should be rejected (401)
        mockMvc.perform(post("/api/some-protected-endpoint")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    // -------------------------------------------------------------------------
    // Validate (blacklisted token)
    // -------------------------------------------------------------------------

    @Test
    void validate_withBlacklistedToken_returns200WithValidFalse() throws Exception {
        registerUser("blacklistval", "blacklistval@example.com", "password123");
        String token = loginAndGetToken("blacklistval", "password123");

        // Blacklist via logout
        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", token))))
                .andExpect(status().isOk());

        // Validate returns false
        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", token))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false));
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private void registerUser(String username, String email, String password) throws Exception {
        Map<String, String> body = Map.of(
                "username", username,
                "email", email,
                "password", password
        );
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isCreated());
    }

    private String loginAndGetToken(String username, String password) throws Exception {
        Map<String, String> body = Map.of("username", username, "password", password);
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).get("token").asText();
    }

    private String loginAndGetRefreshToken(String username, String password) throws Exception {
        Map<String, String> body = Map.of("username", username, "password", password);
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(response).get("refreshToken").asText();
    }

    private String buildExpiredToken(String username) {
        Date issuedAt = new Date(System.currentTimeMillis() - 7_200_000L); // 2 hours ago
        Date expiration = new Date(System.currentTimeMillis() - 3_600_000L); // 1 hour ago
        return Jwts.builder()
                .subject(username)
                .claim("roles", List.of("ROLE_USER"))
                .issuedAt(issuedAt)
                .expiration(expiration)
                .signWith(jwtUtil.getSecretKey())
                .compact();
    }
}
