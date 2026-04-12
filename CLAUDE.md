# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

**Requires Java 21** (default on this machine is Java 8):
```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21)
```

```bash
./mvnw clean compile          # Compile
./mvnw clean package           # Build JAR (includes tests)
./mvnw clean package -DskipTests  # Build JAR without tests
./mvnw spring-boot:run         # Run the application (port 8080)
./mvnw test                    # Run all tests
./mvnw test -Dtest=ClassName   # Run a single test class
./mvnw test -Dtest=ClassName#methodName  # Run a single test method
```

**MySQL required** — the app auto-creates the `security_db` database:
```bash
docker run -d -p 3306:3306 -e MYSQL_ROOT_PASSWORD=root mysql:8.0
```

**Redis required** — used for JWT token blacklisting (logout):
```bash
docker run -d -p 6379:6379 redis:7
```

## Architecture

This is a Spring Boot 3.4.4 security microservice providing JWT-based authentication with OAuth2 Resource Server pattern.

**Authentication flow:**
1. `POST /api/auth/register` — creates user with BCrypt-hashed password, assigns ROLE_USER
2. `POST /api/auth/login` — authenticates via `AuthenticationManager`, returns signed JWT + opaque refresh token with roles in claims
3. `POST /api/auth/refresh` — accepts `{ "refreshToken": "..." }`, validates and rotates the refresh token, returns new JWT + new refresh token
4. `POST /api/auth/logout` — accepts `{ "token": "..." }`, blacklists the JWT in Redis with TTL = remaining time until token expiry. Returns `{ message: "Logged out successfully" }`. Invalid/expired tokens return `{ message: "Token is already invalid" }`. Blacklisted tokens are rejected by both the validate endpoint and the OAuth2 resource server bearer token filter.
5. `POST /api/auth/validate` — accepts `{ "token": "..." }`, validates JWT via `JwtUtil.validateToken()` and checks Redis blacklist (JJWT verifies signature and expiry together); returns `{ valid, username, roles, expiresAt }` on success, `{ valid: false }` for malformed/wrong-signature/expired/blacklisted tokens, 400 for blank token
6. Authenticated requests — Spring's built-in `BearerTokenAuthenticationFilter` (from OAuth2 Resource Server starter) extracts Bearer token, `NimbusJwtDecoder` validates it using the same HMAC secret plus a `TokenBlacklistValidator` that rejects blacklisted tokens, `JwtAuthenticationConverter` maps the `roles` claim to Spring Security authorities

**Password hashing:** `SecurityConfig` exposes a `BCryptPasswordEncoder` bean. `UserService.registerUser()` calls `passwordEncoder.encode(plainText)` before persisting. On login, Spring's `AuthenticationManager` automatically uses the same bean to verify the submitted password against the stored BCrypt hash — no manual comparison in the controller.

**Key design decision:** No custom JWT filter. The `SecurityConfig` wires a `NimbusJwtDecoder` (HMAC HS256) and a `JwtAuthenticationConverter` that reads the `roles` claim with no prefix (role names already contain `ROLE_` prefix). This is the idiomatic Spring Security 6.x approach.

**Layered structure:** `Controller → Service → Repository → Entity` under `com.example.securityservice`.

**Entity relationship:** `User` ↔ `Role` is many-to-many via `user_roles` join table, EAGER fetch (roles are small and always needed for auth). Default roles (`ROLE_USER`, `ROLE_ADMIN`) are seeded via `data.sql` with `INSERT IGNORE`.

**User fields:** `username` (unique, required), `email` (unique, required), `password` (BCrypt, required), `firstName` (optional, max 100 chars), `lastName` (optional, max 100 chars), `enabled` (default true), `roles`.

**Refresh token design:** `RefreshToken` entity stores a UUID string token, a `User` FK, and an `expiryDate` in the `refresh_tokens` table. One active refresh token per user — creating a new one deletes the old one. On use, the token is rotated (old deleted, new issued). `RefreshTokenService` handles create/verify/rotate. `TokenRefreshException` (401) is raised for expired or invalid tokens.

**Token blacklisting:** `TokenBlacklistService` uses `StringRedisTemplate` to store blacklisted JWT tokens in Redis with a key prefix `token:blacklist:` and TTL matching the token's remaining lifetime. `TokenBlacklistValidator` (an `OAuth2TokenValidator<Jwt>`) is wired into `NimbusJwtDecoder` via `DelegatingOAuth2TokenValidator` so blacklisted tokens are also rejected on authenticated endpoints.

**Rate limiting:** `AuthRateLimitFilter` (`OncePerRequestFilter`, Bucket4j) applies per-IP token-bucket throttling on `/api/auth/**`. Two tiers:
- **Strict** — `/api/auth/login`, `/api/auth/register` — default `5 req/min/IP` (credential-stuffing / enumeration protection).
- **Standard** — all other `/api/auth/**` endpoints — default `20 req/min/IP`.

Buckets are keyed by `tier + ":" + clientIp` (X-Forwarded-For first token, else `remoteAddr`) and kept in an in-memory `ConcurrentHashMap` — single-instance only; swap for a Bucket4j Redis proxy manager for multi-instance. On overflow the filter writes `429 Too Many Requests` with `Retry-After: 60` and a JSON body — it short-circuits before Spring Security's authentication filter (wired via `http.addFilterBefore(authRateLimitFilter, UsernamePasswordAuthenticationFilter.class)`). Limits are configurable via `app.rate-limit.auth.strict-per-minute` / `...standard-per-minute`; the test profile raises them to 100000 so existing tests are not throttled, and `AuthRateLimitIntegrationTest` overrides them via `@TestPropertySource` for focused throttle assertions.

**DTOs are Java records** with Jakarta Bean Validation annotations. `GlobalExceptionHandler` (`@RestControllerAdvice`) provides structured JSON error responses for all exception types.

## Testing

Integration tests use H2 in-memory database (MySQL compatibility mode) and embedded Redis (`com.github.codemonstur:embedded-redis`) via the `test` Spring profile. No MySQL or Redis instance needed to run tests.

```bash
./mvnw test                                          # Run all tests
./mvnw test -Dtest=AuthControllerIntegrationTest     # Run auth integration tests
```

**Test profile config:** `src/test/resources/application-test.yml` — H2 with `MODE=MySQL` so `INSERT IGNORE` in `data.sql` works unchanged.

**All test classes must be annotated with `@ActiveProfiles("test")`** — without it, Spring will attempt to connect to MySQL and the context will fail to load.

**`AuthControllerIntegrationTest`** covers:
- `POST /api/auth/register` — valid registration, with optional firstName/lastName, duplicate username/email (409), blank username/invalid email/short password (400)
- **BCrypt hashing** — stored password is a BCrypt hash (not plain text), `passwordEncoder.matches()` verifies the original password against the hash, login succeeds only when BCrypt verification passes
- `POST /api/auth/login` — valid credentials returns JWT + refreshToken + roles, wrong password (401), non-existent user (401), blank credentials (400)
- `POST /api/auth/refresh` — valid refresh token returns new JWT + rotated refresh token (200), old token invalidated after rotation (401), unknown token (401), expired token (401), blank token (400)
- `POST /api/auth/logout` — valid token blacklisted and returns 200, invalid token returns 200 with "already invalid" message, blank token returns 400, blacklisted token rejected by validate endpoint and OAuth2 bearer filter (401)
- `POST /api/auth/validate` — valid token returns 200 with username/roles/expiresAt, malformed/expired/wrong-signature/blacklisted token returns 200 with `valid=false`, blank token returns 400

**`AuthRateLimitIntegrationTest`** — boots its own Spring context (distinct `@TestPropertySource` with `strict-per-minute=3`, `standard-per-minute=3`) and asserts that the 4th `/login` attempt from the same IP returns `429` with `Retry-After`, and the same for `/validate` on the standard tier. Bucket state is singleton-scoped within a context, so the test runs in its own context to stay isolated from `AuthControllerIntegrationTest`.

**`SecurityServiceApplicationTests`** — context load smoke test, uses `@ActiveProfiles("test")` to boot against H2.

## Configuration

Environment variables (no defaults for secrets — the app fails fast on startup if `DB_PASSWORD` or `JWT_SECRET` is missing, via the Spring `${VAR:?message}` placeholder):
- `DB_PASSWORD` (**required**) — MySQL password
- `JWT_SECRET` (**required**) — must be ≥256 bits Base64-encoded for HS256
- `JWT_EXPIRATION_MS` (default: `3600000`) — JWT access token TTL, default 1 hour
- `JWT_REFRESH_EXPIRATION_MS` (default: `604800000`) — refresh token TTL, default 7 days
- `REDIS_HOST` (default: `localhost`) — Redis host
- `REDIS_PORT` (default: `6379`) — Redis port
- `AUTH_RATE_LIMIT_STRICT` (default: `5`) — per-minute per-IP limit on `/api/auth/login` and `/api/auth/register`
- `AUTH_RATE_LIMIT_STANDARD` (default: `20`) — per-minute per-IP limit on the remaining `/api/auth/**` endpoints
- `spring.jpa.hibernate.ddl-auto: update` — Hibernate auto-creates/updates tables (creates `refresh_tokens` table automatically)
