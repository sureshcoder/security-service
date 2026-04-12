package com.example.securityservice.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Validates that AuthRateLimitFilter throttles repeated requests to the strict
 * auth endpoints and returns 429 with a Retry-After header once the bucket is
 * exhausted.
 *
 * Runs in its own Spring context (distinct @TestPropertySource) so the rate-limit
 * bucket state is isolated from the main AuthControllerIntegrationTest, which
 * sets very high limits.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "app.rate-limit.auth.strict-per-minute=3",
        "app.rate-limit.auth.standard-per-minute=3"
})
class AuthRateLimitIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void login_isThrottled_after_strict_limit_is_exceeded() throws Exception {
        String body = "{\"username\":\"no-such-user\",\"password\":\"whatever-pw\"}";

        // First 3 attempts pass the rate limiter and fail auth (401).
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isUnauthorized());
        }

        // Fourth attempt exhausts the bucket → 429 with Retry-After.
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.error").value("Too Many Requests"));
    }

    @Test
    void validate_isThrottled_after_standard_limit_is_exceeded() throws Exception {
        String body = "{\"token\":\"not.a.valid.jwt\"}";

        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/api/auth/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(post("/api/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }
}
