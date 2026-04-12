package com.example.securityservice.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per-IP token-bucket rate limiter for /api/auth/**.
 *
 * Tighter limit ("strict") on credential-validating endpoints (/login, /register)
 * to blunt credential stuffing and account enumeration; looser limit ("standard")
 * on the remaining auth endpoints. Both are configurable; tests raise them
 * out of the way via application-test.yml.
 *
 * In-memory ConcurrentHashMap: fine for single-instance deployments. For a
 * horizontally-scaled deployment, swap in a Bucket4j Redis proxy manager.
 */
public class AuthRateLimitFilter extends OncePerRequestFilter {

    private static final String AUTH_PREFIX = "/api/auth/";
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final long strictLimit;
    private final long standardLimit;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public AuthRateLimitFilter(
            @Value("${app.rate-limit.auth.strict-per-minute:5}") long strictLimit,
            @Value("${app.rate-limit.auth.standard-per-minute:20}") long standardLimit) {
        this.strictLimit = strictLimit;
        this.standardLimit = standardLimit;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String path = request.getRequestURI();
        if (!path.startsWith(AUTH_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        boolean strict = path.equals("/api/auth/login") || path.equals("/api/auth/register");
        long limit = strict ? strictLimit : standardLimit;
        String key = (strict ? "s:" : "n:") + clientIp(request);

        Bucket bucket = buckets.computeIfAbsent(key, k -> newBucket(limit));
        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
            return;
        }

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(WINDOW.toSeconds()));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded for authentication endpoints\"}");
    }

    private static Bucket newBucket(long limit) {
        return Bucket.builder()
                .addLimit(Bandwidth.classic(limit, Refill.intervally(limit, WINDOW)))
                .build();
    }

    private static String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            int comma = xff.indexOf(',');
            return (comma > 0 ? xff.substring(0, comma) : xff).trim();
        }
        return request.getRemoteAddr();
    }
}
