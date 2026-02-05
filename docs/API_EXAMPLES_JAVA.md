# API Usage Examples - Java

Complete guide for using the governed Mem0 API with Java.

---

## Table of Contents

- [Setup](#setup)
- [Java Client Library](#java-client-library)
- [Basic Operations](#basic-operations)
- [Multi-Tenant Operations](#multi-tenant-operations)
- [Spring Boot Integration](#spring-boot-integration)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Advanced Patterns](#advanced-patterns)

---

## Setup

### Maven Dependencies

**`pom.xml`:**

```xml
<project>
  <properties>
    <java.version>17</java.version>
    <okhttp.version>4.12.0</okhttp.version>
    <jackson.version>2.16.0</jackson.version>
    <lombok.version>1.18.30</lombok.version>
  </properties>

  <dependencies>
    <!-- HTTP Client -->
    <dependency>
      <groupId>com.squareup.okhttp3</groupId>
      <artifactId>okhttp</artifactId>
      <version>${okhttp.version}</version>
    </dependency>

    <!-- JSON Processing -->
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>

    <!-- Lombok (optional, for cleaner code) -->
    <dependency>
      <groupId>org.projectlombok</groupId>
      <artifactId>lombok</artifactId>
      <version>${lombok.version}</version>
      <scope>provided</scope>
    </dependency>

    <!-- SLF4J Logging -->
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.9</version>
    </dependency>
  </dependencies>
</project>
```

### Gradle Dependencies

**`build.gradle`:**

```groovy
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
}

dependencies {
    implementation 'com.squareup.okhttp3:okhttp:4.12.0'
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.16.0'
    implementation 'org.slf4j:slf4j-api:2.0.9'
    compileOnly 'org.projectlombok:lombok:1.18.30'
    annotationProcessor 'org.projectlombok:lombok:1.18.30'
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
}
```

---

## Java Client Library

### Complete Java Client

**`GovernedMem0Client.java`:**

```java
package com.example.mem0;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
public class GovernedMem0Client implements AutoCloseable {

    private final String gatewayUrl;
    private final GovernanceHeaders headers;
    private final OkHttpClient httpClient;
    private final ObjectMapper objectMapper;

    @Data
    @Builder
    public static class GovernanceHeaders {
        private String userId;      // X-User-Id
        private String userRole;    // X-User-Role
        private String tenantId;    // X-Tenant-Id
    }

    @Data
    @Builder
    public static class MemoryMessage {
        private String role;
        private String content;
    }

    @Data
    @Builder
    public static class CreateMemoryRequest {
        private List<MemoryMessage> messages;
        private String user_id;
    }

    @Data
    public static class Memory {
        private String id;
        private String content;
        private String user_id;
        private String created_at;
    }

    @Data
    public static class MemoryListResponse {
        private List<Memory> memories;
    }

    @Data
    @Builder
    public static class SearchMemoryRequest {
        private String query;
        private String user_id;
        private Integer limit;
    }

    @Data
    public static class SearchMemoryResponse {
        private List<Memory> results;
    }

    @Data
    public static class ErrorResponse {
        private String detail;
    }

    // Custom Exceptions
    public static class AccessDeniedException extends Exception {
        public AccessDeniedException(String message) {
            super(message);
        }
    }

    public static class RateLimitException extends Exception {
        private final int retryAfter;

        public RateLimitException(String message, int retryAfter) {
            super(message);
            this.retryAfter = retryAfter;
        }

        public int getRetryAfter() {
            return retryAfter;
        }
    }

    public GovernedMem0Client(String gatewayUrl, GovernanceHeaders headers) {
        this.gatewayUrl = gatewayUrl;
        this.headers = headers;
        this.objectMapper = new ObjectMapper();

        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
    }

    /**
     * Build request with governance headers
     */
    private Request.Builder buildRequest(String path) {
        return new Request.Builder()
            .url(gatewayUrl + path)
            .header("X-User-Id", headers.getUserId())
            .header("X-User-Role", headers.getUserRole())
            .header("X-Tenant-Id", headers.getTenantId());
    }

    /**
     * Handle HTTP response and errors
     */
    private <T> T handleResponse(Response response, Class<T> responseClass)
            throws IOException, AccessDeniedException, RateLimitException {

        if (!response.isSuccessful()) {
            String body = response.body() != null ? response.body().string() : "";
            ErrorResponse error = null;

            try {
                error = objectMapper.readValue(body, ErrorResponse.class);
            } catch (Exception e) {
                log.warn("Failed to parse error response", e);
            }

            String detail = error != null ? error.getDetail() : "Unknown error";

            switch (response.code()) {
                case 403:
                    throw new AccessDeniedException(detail);
                case 429:
                    int retryAfter = Integer.parseInt(
                        response.header("Retry-After", "60")
                    );
                    throw new RateLimitException(detail, retryAfter);
                case 400:
                    throw new IOException("Bad Request: " + detail);
                case 503:
                    throw new IOException("Service temporarily unavailable");
                default:
                    throw new IOException("HTTP " + response.code() + ": " + detail);
            }
        }

        if (response.body() == null) {
            return null;
        }

        String body = response.body().string();
        return objectMapper.readValue(body, responseClass);
    }

    /**
     * Create a new memory
     */
    public Memory createMemory(CreateMemoryRequest request)
            throws IOException, AccessDeniedException, RateLimitException {

        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(request),
            MediaType.get("application/json")
        );

        Request httpRequest = buildRequest("/memories")
            .post(body)
            .build();

        try (Response response = httpClient.newCall(httpRequest).execute()) {
            return handleResponse(response, Memory.class);
        }
    }

    /**
     * Get all memories for a user
     */
    public List<Memory> getMemories(String userId)
            throws IOException, AccessDeniedException, RateLimitException {

        HttpUrl url = HttpUrl.parse(gatewayUrl + "/memories")
            .newBuilder()
            .addQueryParameter("user_id", userId)
            .build();

        Request request = buildRequest("/memories")
            .url(url)
            .get()
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            MemoryListResponse result = handleResponse(response, MemoryListResponse.class);
            return result != null ? result.getMemories() : List.of();
        }
    }

    /**
     * Search memories
     */
    public List<Memory> searchMemories(SearchMemoryRequest request)
            throws IOException, AccessDeniedException, RateLimitException {

        RequestBody body = RequestBody.create(
            objectMapper.writeValueAsString(request),
            MediaType.get("application/json")
        );

        Request httpRequest = buildRequest("/memories/search")
            .post(body)
            .build();

        try (Response response = httpClient.newCall(httpRequest).execute()) {
            SearchMemoryResponse result = handleResponse(response, SearchMemoryResponse.class);
            return result != null ? result.getResults() : List.of();
        }
    }

    /**
     * Delete a memory (admin only)
     */
    public void deleteMemory(String memoryId)
            throws IOException, AccessDeniedException, RateLimitException {

        Request request = buildRequest("/memories/" + memoryId)
            .delete()
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                handleResponse(response, Void.class);
            }
        }
    }

    /**
     * Get current governance context
     */
    public GovernanceHeaders getContext() {
        return headers;
    }

    @Override
    public void close() {
        httpClient.dispatcher().executorService().shutdown();
        httpClient.connectionPool().evictAll();
    }
}
```

---

## Basic Operations

### Create and Retrieve Memories

```java
package com.example.mem0;

import java.util.List;

public class BasicExample {

    public static void main(String[] args) {
        // Initialize client
        GovernedMem0Client.GovernanceHeaders headers =
            GovernedMem0Client.GovernanceHeaders.builder()
                .userId("agent-001")
                .userRole("agent-writer")
                .tenantId("tenant-acme")
                .build();

        try (GovernedMem0Client client = new GovernedMem0Client(
                "http://localhost:9000", headers)) {

            // Create a memory
            GovernedMem0Client.CreateMemoryRequest request =
                GovernedMem0Client.CreateMemoryRequest.builder()
                    .messages(List.of(
                        GovernedMem0Client.MemoryMessage.builder()
                            .role("user")
                            .content("My favorite programming language is Java")
                            .build()
                    ))
                    .user_id("user-alice")
                    .build();

            GovernedMem0Client.Memory memory = client.createMemory(request);
            System.out.println("Created memory: " + memory.getId());

            // Retrieve memories
            List<GovernedMem0Client.Memory> memories =
                client.getMemories("user-alice");

            System.out.println("Found " + memories.size() + " memories");
            memories.forEach(m -> System.out.println("- " + m.getContent()));

            // Search memories
            GovernedMem0Client.SearchMemoryRequest searchRequest =
                GovernedMem0Client.SearchMemoryRequest.builder()
                    .query("programming language")
                    .user_id("user-alice")
                    .build();

            List<GovernedMem0Client.Memory> results =
                client.searchMemories(searchRequest);

            System.out.println("Search found " + results.size() + " results");

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
```

---

## Multi-Tenant Operations

### Multi-Tenant Manager

```java
package com.example.mem0;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MultiTenantMemoryManager implements AutoCloseable {

    private final String gatewayUrl;
    private final Map<String, GovernedMem0Client> clients;

    public MultiTenantMemoryManager(String gatewayUrl) {
        this.gatewayUrl = gatewayUrl;
        this.clients = new HashMap<>();
    }

    /**
     * Get or create a client for specific tenant
     */
    public GovernedMem0Client getTenantClient(
            String tenantId, String userId, String role) {

        String key = String.format("%s:%s:%s", tenantId, userId, role);

        return clients.computeIfAbsent(key, k -> {
            GovernedMem0Client.GovernanceHeaders headers =
                GovernedMem0Client.GovernanceHeaders.builder()
                    .userId(userId)
                    .userRole(role)
                    .tenantId(tenantId)
                    .build();

            return new GovernedMem0Client(gatewayUrl, headers);
        });
    }

    /**
     * Create memory for specific tenant
     */
    public GovernedMem0Client.Memory createTenantMemory(
            String tenantId, String userId, String actorId, String content)
            throws Exception {

        GovernedMem0Client client = getTenantClient(tenantId, actorId, "agent-writer");

        GovernedMem0Client.CreateMemoryRequest request =
            GovernedMem0Client.CreateMemoryRequest.builder()
                .messages(List.of(
                    GovernedMem0Client.MemoryMessage.builder()
                        .role("user")
                        .content(content)
                        .build()
                ))
                .user_id(userId)
                .build();

        return client.createMemory(request);
    }

    /**
     * Get memories for specific tenant
     */
    public List<GovernedMem0Client.Memory> getTenantMemories(
            String tenantId, String userId, String actorId)
            throws Exception {

        GovernedMem0Client client = getTenantClient(tenantId, actorId, "agent-reader");
        return client.getMemories(userId);
    }

    @Override
    public void close() {
        clients.values().forEach(GovernedMem0Client::close);
        clients.clear();
    }

    public static void main(String[] args) {
        try (MultiTenantMemoryManager manager =
                new MultiTenantMemoryManager("http://localhost:9000")) {

            // Tenant ACME
            manager.createTenantMemory(
                "tenant-acme",
                "user-alice",
                "agent-acme-1",
                "ACME Corp confidential data"
            );

            // Tenant Globex (isolated from ACME)
            manager.createTenantMemory(
                "tenant-globex",
                "user-bob",
                "agent-globex-1",
                "Globex Inc confidential data"
            );

            // Retrieve ACME memories
            List<GovernedMem0Client.Memory> acmeMemories =
                manager.getTenantMemories("tenant-acme", "user-alice", "agent-acme-1");

            System.out.println("ACME memories: " + acmeMemories.size());

            // Cross-tenant access is blocked
            try {
                GovernedMem0Client client = manager.getTenantClient(
                    "tenant-globex", "agent-globex-1", "agent-reader"
                );
                client.getMemories("user-alice"); // Alice belongs to ACME
            } catch (GovernedMem0Client.AccessDeniedException e) {
                System.out.println("Cross-tenant access blocked: " + e.getMessage());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

## Spring Boot Integration

### Configuration

```java
package com.example.mem0.config;

import com.example.mem0.GovernedMem0Client;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.web.context.WebApplicationContext;

@Configuration
public class Mem0Config {

    @Value("${mem0.gateway.url:http://localhost:9000}")
    private String gatewayUrl;

    @Bean
    public String mem0GatewayUrl() {
        return gatewayUrl;
    }
}
```

### Interceptor for Governance Headers

```java
package com.example.mem0.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class GovernanceInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request,
                           HttpServletResponse response,
                           Object handler) throws Exception {

        String userId = request.getHeader("X-User-Id");
        String userRole = request.getHeader("X-User-Role");
        String tenantId = request.getHeader("X-Tenant-Id");

        // Validate required headers
        if (userId == null || userRole == null || tenantId == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write(
                "{\"error\":\"Missing required governance headers\"}"
            );
            return false;
        }

        // Store in request attributes for controller access
        request.setAttribute("governance.userId", userId);
        request.setAttribute("governance.userRole", userRole);
        request.setAttribute("governance.tenantId", tenantId);

        return true;
    }
}
```

### REST Controller

```java
package com.example.mem0.controller;

import com.example.mem0.GovernedMem0Client;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/memories")
@RequiredArgsConstructor
public class MemoryController {

    @Value("${mem0.gateway.url}")
    private String gatewayUrl;

    @Data
    public static class CreateMemoryRequest {
        private String content;
        private String user_id;
    }

    /**
     * Create Mem0 client from request attributes
     */
    private GovernedMem0Client createClient(HttpServletRequest request) {
        GovernedMem0Client.GovernanceHeaders headers =
            GovernedMem0Client.GovernanceHeaders.builder()
                .userId((String) request.getAttribute("governance.userId"))
                .userRole((String) request.getAttribute("governance.userRole"))
                .tenantId((String) request.getAttribute("governance.tenantId"))
                .build();

        return new GovernedMem0Client(gatewayUrl, headers);
    }

    @PostMapping
    public ResponseEntity<?> createMemory(
            @RequestBody CreateMemoryRequest request,
            HttpServletRequest httpRequest) {

        try (GovernedMem0Client client = createClient(httpRequest)) {
            GovernedMem0Client.CreateMemoryRequest mem0Request =
                GovernedMem0Client.CreateMemoryRequest.builder()
                    .messages(List.of(
                        GovernedMem0Client.MemoryMessage.builder()
                            .role("user")
                            .content(request.getContent())
                            .build()
                    ))
                    .user_id(request.getUser_id())
                    .build();

            GovernedMem0Client.Memory memory = client.createMemory(mem0Request);

            return ResponseEntity.ok(Map.of(
                "success", true,
                "memory", memory
            ));

        } catch (GovernedMem0Client.AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("error", "Access Denied", "message", e.getMessage()));

        } catch (GovernedMem0Client.RateLimitException e) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header("Retry-After", String.valueOf(e.getRetryAfter()))
                .body(Map.of(
                    "error", "Rate Limit Exceeded",
                    "retryAfter", e.getRetryAfter()
                ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Internal Error", "message", e.getMessage()));
        }
    }

    @GetMapping("/{userId}")
    public ResponseEntity<?> getMemories(
            @PathVariable String userId,
            HttpServletRequest httpRequest) {

        try (GovernedMem0Client client = createClient(httpRequest)) {
            List<GovernedMem0Client.Memory> memories = client.getMemories(userId);

            return ResponseEntity.ok(Map.of(
                "success", true,
                "count", memories.size(),
                "memories", memories
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", e.getMessage()));
        }
    }
}
```

### Web Configuration

```java
package com.example.mem0.config;

import com.example.mem0.interceptor.GovernanceInterceptor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebConfig implements WebMvcConfigurer {

    private final GovernanceInterceptor governanceInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(governanceInterceptor)
                .addPathPatterns("/api/**");
    }
}
```

---

## Error Handling

### Robust Error Handling with Retry

```java
package com.example.mem0;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;

@Slf4j
public class RobustMemoryOperations {

    public static GovernedMem0Client.Memory createMemoryWithRetry(
            GovernedMem0Client client,
            GovernedMem0Client.CreateMemoryRequest request,
            int maxRetries) {

        int attempt = 0;
        Exception lastException = null;

        while (attempt < maxRetries) {
            try {
                return client.createMemory(request);

            } catch (GovernedMem0Client.AccessDeniedException e) {
                log.error("Access denied: {}", e.getMessage());
                return null; // Don't retry on permission errors

            } catch (GovernedMem0Client.RateLimitException e) {
                log.warn("Rate limited. Waiting {}s...", e.getRetryAfter());
                sleep(e.getRetryAfter() * 1000);
                attempt++;
                lastException = e;
                continue;

            } catch (Exception e) {
                if (e.getMessage().contains("Service temporarily unavailable")) {
                    log.warn("Service unavailable. Retry {}/{}...", attempt + 1, maxRetries);
                    sleep(5000);
                    attempt++;
                    lastException = e;
                    continue;
                }

                log.error("Unexpected error: {}", e.getMessage());
                return null;
            }
        }

        log.error("Failed after {} attempts", maxRetries, lastException);
        return null;
    }

    private static void sleep(long millis) {
        try {
            TimeUnit.MILLISECONDS.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static void main(String[] args) {
        GovernedMem0Client.GovernanceHeaders headers =
            GovernedMem0Client.GovernanceHeaders.builder()
                .userId("agent-001")
                .userRole("agent-writer")
                .tenantId("tenant-acme")
                .build();

        try (GovernedMem0Client client = new GovernedMem0Client(
                "http://localhost:9000", headers)) {

            GovernedMem0Client.CreateMemoryRequest request =
                GovernedMem0Client.CreateMemoryRequest.builder()
                    .messages(List.of(
                        GovernedMem0Client.MemoryMessage.builder()
                            .role("user")
                            .content("Test content")
                            .build()
                    ))
                    .user_id("user-alice")
                    .build();

            GovernedMem0Client.Memory memory = createMemoryWithRetry(client, request, 3);

            if (memory != null) {
                System.out.println("Success: " + memory.getId());
            } else {
                System.err.println("Failed to create memory");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

## Rate Limiting

### Batch Processing with Rate Limit Awareness

```java
package com.example.mem0;

import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Slf4j
public class BatchProcessor {

    public static <T, R> List<R> processBatch(
            List<T> items,
            BatchOperation<T, R> operation,
            int batchSize,
            long delayMillis) {

        List<R> results = new ArrayList<>();

        for (int i = 0; i < items.size(); i += batchSize) {
            int end = Math.min(i + batchSize, items.size());
            List<T> batch = items.subList(i, end);

            log.info("Processing batch {}/{}", (i / batchSize) + 1,
                    (items.size() + batchSize - 1) / batchSize);

            for (T item : batch) {
                try {
                    R result = RobustMemoryOperations.withRetry(() -> operation.process(item), 3);
                    if (result != null) {
                        results.add(result);
                    }
                } catch (Exception e) {
                    log.error("Failed to process item: {}", e.getMessage());
                }
            }

            // Delay between batches
            if (end < items.size()) {
                sleep(delayMillis);
            }
        }

        return results;
    }

    @FunctionalInterface
    public interface BatchOperation<T, R> {
        R process(T item) throws Exception;
    }

    private static void sleep(long millis) {
        try {
            TimeUnit.MILLISECONDS.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static void main(String[] args) {
        GovernedMem0Client.GovernanceHeaders headers =
            GovernedMem0Client.GovernanceHeaders.builder()
                .userId("admin-001")
                .userRole("admin") // Admin gets 500 req/min
                .tenantId("tenant-acme")
                .build();

        try (GovernedMem0Client client = new GovernedMem0Client(
                "http://localhost:9000", headers)) {

            // Create 100 test memories
            List<String> contents = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                contents.add("Memory " + i);
            }

            List<GovernedMem0Client.Memory> results = processBatch(
                contents,
                content -> {
                    GovernedMem0Client.CreateMemoryRequest request =
                        GovernedMem0Client.CreateMemoryRequest.builder()
                            .messages(List.of(
                                GovernedMem0Client.MemoryMessage.builder()
                                    .role("user")
                                    .content(content)
                                    .build()
                            ))
                            .user_id("user-alice")
                            .build();
                    return client.createMemory(request);
                },
                50,   // 50 per batch
                1500  // 1.5s delay between batches
            );

            log.info("Imported {}/{} memories", results.size(), contents.size());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

---

## Advanced Patterns

### Connection Pool Configuration

```java
package com.example.mem0;

import okhttp3.ConnectionPool;
import okhttp3.OkHttpClient;

import java.util.concurrent.TimeUnit;

public class PooledMem0Client extends GovernedMem0Client {

    public PooledMem0Client(String gatewayUrl, GovernanceHeaders headers) {
        super(gatewayUrl, headers);
    }

    /**
     * Create HTTP client with custom connection pool
     */
    protected static OkHttpClient createPooledHttpClient() {
        ConnectionPool pool = new ConnectionPool(
            50,    // maxIdleConnections
            5,     // keepAliveDuration
            TimeUnit.MINUTES
        );

        return new OkHttpClient.Builder()
            .connectionPool(pool)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build();
    }
}
```

---

## Application Properties

**`application.properties` (Spring Boot):**

```properties
# Mem0 Gateway Configuration
mem0.gateway.url=http://localhost:9000

# Logging
logging.level.com.example.mem0=DEBUG
logging.level.okhttp3=INFO

# Server
server.port=8080
```

**`application.yml` (Spring Boot):**

```yaml
mem0:
  gateway:
    url: http://localhost:9000

logging:
  level:
    com.example.mem0: DEBUG
    okhttp3: INFO

server:
  port: 8080
```

---

## Next Steps

- **[Python Examples](./API_EXAMPLES.md)** - Python SDK examples
- **[JavaScript/TypeScript](./API_EXAMPLES_JAVASCRIPT.md)** - Node.js examples
- **[Common Scenarios](./COMMON_SCENARIOS.md)** - Multi-tenant, custom roles
- **[Quick Start](./QUICKSTART.md)** - Get started from scratch

---

**Need help?** [Open an issue](https://github.com/your-org/oss-governance-for-mem0/issues)
