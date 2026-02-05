# API Usage Examples - Go

Complete guide for using the governed Mem0 API with Go.

---

## Table of Contents

- [Setup](#setup)
- [Go Client Library](#go-client-library)
- [Basic Operations](#basic-operations)
- [Multi-Tenant Operations](#multi-tenant-operations)
- [HTTP Middleware](#http-middleware)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Advanced Patterns](#advanced-patterns)

---

## Setup

### Initialize Go Module

```bash
mkdir mem0-governance-client
cd mem0-governance-client
go mod init github.com/yourorg/mem0-governance-client
```

### Install Dependencies

```bash
go get github.com/gin-gonic/gin@v1.9.1
go get github.com/sirupsen/logrus@v1.9.3
```

**`go.mod`:**

```go
module github.com/yourorg/mem0-governance-client

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/sirupsen/logrus v1.9.3
)
```

---

## Go Client Library

### Complete Go Client

**`client/mem0_client.go`:**

```go
package client

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "time"
)

// GovernanceHeaders contains required governance headers
type GovernanceHeaders struct {
    UserID   string // X-User-Id
    UserRole string // X-User-Role
    TenantID string // X-Tenant-Id
}

// MemoryMessage represents a message in memory creation
type MemoryMessage struct {
    Role    string `json:"role"`
    Content string `json:"content"`
}

// CreateMemoryRequest is the request body for creating memories
type CreateMemoryRequest struct {
    Messages []MemoryMessage `json:"messages"`
    UserID   string          `json:"user_id"`
}

// Memory represents a Mem0 memory object
type Memory struct {
    ID        string    `json:"id"`
    Content   string    `json:"content"`
    UserID    string    `json:"user_id"`
    CreatedAt time.Time `json:"created_at"`
}

// MemoryListResponse is the response for listing memories
type MemoryListResponse struct {
    Memories []Memory `json:"memories"`
}

// SearchMemoryRequest is the request for searching memories
type SearchMemoryRequest struct {
    Query  string `json:"query"`
    UserID string `json:"user_id"`
    Limit  *int   `json:"limit,omitempty"`
}

// SearchMemoryResponse is the response for memory search
type SearchMemoryResponse struct {
    Results []Memory `json:"results"`
}

// ErrorResponse represents an API error
type ErrorResponse struct {
    Detail string `json:"detail"`
}

// Custom errors
var (
    ErrAccessDenied       = fmt.Errorf("access denied")
    ErrRateLimitExceeded  = fmt.Errorf("rate limit exceeded")
    ErrBadRequest         = fmt.Errorf("bad request")
    ErrServiceUnavailable = fmt.Errorf("service unavailable")
)

// RateLimitError contains retry information
type RateLimitError struct {
    Message    string
    RetryAfter int
}

func (e *RateLimitError) Error() string {
    return fmt.Sprintf("%s (retry after %d seconds)", e.Message, e.RetryAfter)
}

// GovernedMem0Client is the client for governed Mem0 API
type GovernedMem0Client struct {
    gatewayURL string
    headers    GovernanceHeaders
    httpClient *http.Client
}

// NewGovernedMem0Client creates a new client
func NewGovernedMem0Client(gatewayURL string, headers GovernanceHeaders) *GovernedMem0Client {
    return &GovernedMem0Client{
        gatewayURL: gatewayURL,
        headers:    headers,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// buildRequest creates an HTTP request with governance headers
func (c *GovernedMem0Client) buildRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
    req, err := http.NewRequestWithContext(ctx, method, c.gatewayURL+path, body)
    if err != nil {
        return nil, err
    }

    req.Header.Set("X-User-Id", c.headers.UserID)
    req.Header.Set("X-User-Role", c.headers.UserRole)
    req.Header.Set("X-Tenant-Id", c.headers.TenantID)

    if body != nil {
        req.Header.Set("Content-Type", "application/json")
    }

    return req, nil
}

// handleResponse processes HTTP response and errors
func (c *GovernedMem0Client) handleResponse(resp *http.Response, result interface{}) error {
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("failed to read response: %w", err)
    }

    if resp.StatusCode >= 400 {
        var errResp ErrorResponse
        if err := json.Unmarshal(body, &errResp); err != nil {
            errResp.Detail = string(body)
        }

        switch resp.StatusCode {
        case http.StatusForbidden:
            return fmt.Errorf("%w: %s", ErrAccessDenied, errResp.Detail)

        case http.StatusTooManyRequests:
            retryAfter, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
            if retryAfter == 0 {
                retryAfter = 60
            }
            return &RateLimitError{
                Message:    errResp.Detail,
                RetryAfter: retryAfter,
            }

        case http.StatusBadRequest:
            return fmt.Errorf("%w: %s", ErrBadRequest, errResp.Detail)

        case http.StatusServiceUnavailable:
            return fmt.Errorf("%w: %s", ErrServiceUnavailable, errResp.Detail)

        default:
            return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errResp.Detail)
        }
    }

    if result != nil && len(body) > 0 {
        if err := json.Unmarshal(body, result); err != nil {
            return fmt.Errorf("failed to unmarshal response: %w", err)
        }
    }

    return nil
}

// CreateMemory creates a new memory
func (c *GovernedMem0Client) CreateMemory(ctx context.Context, req CreateMemoryRequest) (*Memory, error) {
    body, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    httpReq, err := c.buildRequest(ctx, http.MethodPost, "/memories", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }

    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }

    var memory Memory
    if err := c.handleResponse(resp, &memory); err != nil {
        return nil, err
    }

    return &memory, nil
}

// GetMemories retrieves all memories for a user
func (c *GovernedMem0Client) GetMemories(ctx context.Context, userID string) ([]Memory, error) {
    path := fmt.Sprintf("/memories?user_id=%s", userID)

    httpReq, err := c.buildRequest(ctx, http.MethodGet, path, nil)
    if err != nil {
        return nil, err
    }

    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }

    var result MemoryListResponse
    if err := c.handleResponse(resp, &result); err != nil {
        return nil, err
    }

    if result.Memories == nil {
        return []Memory{}, nil
    }

    return result.Memories, nil
}

// SearchMemories searches for memories
func (c *GovernedMem0Client) SearchMemories(ctx context.Context, req SearchMemoryRequest) ([]Memory, error) {
    body, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %w", err)
    }

    httpReq, err := c.buildRequest(ctx, http.MethodPost, "/memories/search", bytes.NewReader(body))
    if err != nil {
        return nil, err
    }

    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }

    var result SearchMemoryResponse
    if err := c.handleResponse(resp, &result); err != nil {
        return nil, err
    }

    if result.Results == nil {
        return []Memory{}, nil
    }

    return result.Results, nil
}

// DeleteMemory deletes a memory (admin only)
func (c *GovernedMem0Client) DeleteMemory(ctx context.Context, memoryID string) error {
    path := fmt.Sprintf("/memories/%s", memoryID)

    httpReq, err := c.buildRequest(ctx, http.MethodDelete, path, nil)
    if err != nil {
        return err
    }

    resp, err := c.httpClient.Do(httpReq)
    if err != nil {
        return fmt.Errorf("request failed: %w", err)
    }

    return c.handleResponse(resp, nil)
}

// GetContext returns the current governance context
func (c *GovernedMem0Client) GetContext() GovernanceHeaders {
    return c.headers
}
```

---

## Basic Operations

### Create and Retrieve Memories

**`examples/basic/main.go`:**

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/yourorg/mem0-governance-client/client"
)

func main() {
    // Initialize client
    headers := client.GovernanceHeaders{
        UserID:   "agent-001",
        UserRole: "agent-writer",
        TenantID: "tenant-acme",
    }

    c := client.NewGovernedMem0Client("http://localhost:9000", headers)
    ctx := context.Background()

    // Create a memory
    createReq := client.CreateMemoryRequest{
        Messages: []client.MemoryMessage{
            {
                Role:    "user",
                Content: "My favorite programming language is Go",
            },
        },
        UserID: "user-alice",
    }

    memory, err := c.CreateMemory(ctx, createReq)
    if err != nil {
        log.Fatalf("Failed to create memory: %v", err)
    }
    fmt.Printf("Created memory: %s\n", memory.ID)

    // Retrieve memories
    memories, err := c.GetMemories(ctx, "user-alice")
    if err != nil {
        log.Fatalf("Failed to get memories: %v", err)
    }

    fmt.Printf("Found %d memories\n", len(memories))
    for _, m := range memories {
        fmt.Printf("- %s\n", m.Content)
    }

    // Search memories
    searchReq := client.SearchMemoryRequest{
        Query:  "programming language",
        UserID: "user-alice",
    }

    results, err := c.SearchMemories(ctx, searchReq)
    if err != nil {
        log.Fatalf("Failed to search memories: %v", err)
    }

    fmt.Printf("Search found %d results\n", len(results))
}
```

Run:
```bash
go run examples/basic/main.go
```

---

## Multi-Tenant Operations

### Multi-Tenant Manager

**`client/multitenant.go`:**

```go
package client

import (
    "context"
    "fmt"
    "sync"
)

// MultiTenantMemoryManager manages multiple tenant clients
type MultiTenantMemoryManager struct {
    gatewayURL string
    clients    map[string]*GovernedMem0Client
    mu         sync.RWMutex
}

// NewMultiTenantMemoryManager creates a new multi-tenant manager
func NewMultiTenantMemoryManager(gatewayURL string) *MultiTenantMemoryManager {
    return &MultiTenantMemoryManager{
        gatewayURL: gatewayURL,
        clients:    make(map[string]*GovernedMem0Client),
    }
}

// GetTenantClient gets or creates a client for a specific tenant
func (m *MultiTenantMemoryManager) GetTenantClient(tenantID, userID, role string) *GovernedMem0Client {
    key := fmt.Sprintf("%s:%s:%s", tenantID, userID, role)

    m.mu.RLock()
    client, exists := m.clients[key]
    m.mu.RUnlock()

    if exists {
        return client
    }

    m.mu.Lock()
    defer m.mu.Unlock()

    // Double-check after acquiring write lock
    if client, exists := m.clients[key]; exists {
        return client
    }

    headers := GovernanceHeaders{
        UserID:   userID,
        UserRole: role,
        TenantID: tenantID,
    }

    client = NewGovernedMem0Client(m.gatewayURL, headers)
    m.clients[key] = client

    return client
}

// CreateTenantMemory creates a memory for a specific tenant
func (m *MultiTenantMemoryManager) CreateTenantMemory(
    ctx context.Context,
    tenantID, userID, actorID, content string,
) (*Memory, error) {
    client := m.GetTenantClient(tenantID, actorID, "agent-writer")

    req := CreateMemoryRequest{
        Messages: []MemoryMessage{
            {Role: "user", Content: content},
        },
        UserID: userID,
    }

    return client.CreateMemory(ctx, req)
}

// GetTenantMemories retrieves memories for a specific tenant
func (m *MultiTenantMemoryManager) GetTenantMemories(
    ctx context.Context,
    tenantID, userID, actorID string,
) ([]Memory, error) {
    client := m.GetTenantClient(tenantID, actorID, "agent-reader")
    return client.GetMemories(ctx, userID)
}
```

**`examples/multitenant/main.go`:**

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"

    "github.com/yourorg/mem0-governance-client/client"
)

func main() {
    manager := client.NewMultiTenantMemoryManager("http://localhost:9000")
    ctx := context.Background()

    // Tenant ACME
    _, err := manager.CreateTenantMemory(
        ctx,
        "tenant-acme",
        "user-alice",
        "agent-acme-1",
        "ACME Corp confidential data",
    )
    if err != nil {
        log.Fatalf("Failed to create ACME memory: %v", err)
    }

    // Tenant Globex (isolated from ACME)
    _, err = manager.CreateTenantMemory(
        ctx,
        "tenant-globex",
        "user-bob",
        "agent-globex-1",
        "Globex Inc confidential data",
    )
    if err != nil {
        log.Fatalf("Failed to create Globex memory: %v", err)
    }

    // Retrieve ACME memories
    acmeMemories, err := manager.GetTenantMemories(
        ctx,
        "tenant-acme",
        "user-alice",
        "agent-acme-1",
    )
    if err != nil {
        log.Fatalf("Failed to get ACME memories: %v", err)
    }
    fmt.Printf("ACME memories: %d\n", len(acmeMemories))

    // Cross-tenant access is blocked
    globexClient := manager.GetTenantClient("tenant-globex", "agent-globex-1", "agent-reader")
    _, err = globexClient.GetMemories(ctx, "user-alice") // Alice belongs to ACME

    if errors.Is(err, client.ErrAccessDenied) {
        fmt.Println("Cross-tenant access blocked:", err)
    }
}
```

---

## HTTP Middleware

### Gin Framework Middleware

**`middleware/governance.go`:**

```go
package middleware

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/yourorg/mem0-governance-client/client"
)

// GovernanceContext key for storing governance headers in context
const GovernanceContext = "governance"

// GovernanceMiddleware extracts and validates governance headers
func GovernanceMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        userID := c.GetHeader("X-User-Id")
        userRole := c.GetHeader("X-User-Role")
        tenantID := c.GetHeader("X-Tenant-Id")

        // Validate required headers
        if userID == "" || userRole == "" || tenantID == "" {
            c.JSON(http.StatusBadRequest, gin.H{
                "error": "Missing required governance headers",
                "required": []string{
                    "X-User-Id",
                    "X-User-Role",
                    "X-Tenant-Id",
                },
            })
            c.Abort()
            return
        }

        // Store in context
        headers := client.GovernanceHeaders{
            UserID:   userID,
            UserRole: userRole,
            TenantID: tenantID,
        }

        c.Set(GovernanceContext, headers)
        c.Next()
    }
}

// GetGovernanceHeaders retrieves governance headers from context
func GetGovernanceHeaders(c *gin.Context) (client.GovernanceHeaders, bool) {
    value, exists := c.Get(GovernanceContext)
    if !exists {
        return client.GovernanceHeaders{}, false
    }

    headers, ok := value.(client.GovernanceHeaders)
    return headers, ok
}
```

### Gin Application

**`examples/gin-api/main.go`:**

```go
package main

import (
    "errors"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/yourorg/mem0-governance-client/client"
    "github.com/yourorg/mem0-governance-client/middleware"
)

const gatewayURL = "http://localhost:9000"

type CreateMemoryRequest struct {
    Content string `json:"content" binding:"required"`
    UserID  string `json:"user_id" binding:"required"`
}

func main() {
    r := gin.Default()

    // Apply governance middleware
    api := r.Group("/api")
    api.Use(middleware.GovernanceMiddleware())

    // Create memory endpoint
    api.POST("/memories", createMemory)

    // Get memories endpoint
    api.GET("/memories/:userId", getMemories)

    // Search memories endpoint
    api.POST("/memories/search", searchMemories)

    r.Run(":8080")
}

func createClient(c *gin.Context) (*client.GovernedMem0Client, error) {
    headers, ok := middleware.GetGovernanceHeaders(c)
    if !ok {
        return nil, errors.New("governance headers not found")
    }

    return client.NewGovernedMem0Client(gatewayURL, headers), nil
}

func createMemory(c *gin.Context) {
    var req CreateMemoryRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    mem0Client, err := createClient(c)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    memory, err := mem0Client.CreateMemory(c.Request.Context(), client.CreateMemoryRequest{
        Messages: []client.MemoryMessage{
            {Role: "user", Content: req.Content},
        },
        UserID: req.UserID,
    })

    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "memory":  memory,
    })
}

func getMemories(c *gin.Context) {
    userID := c.Param("userId")

    mem0Client, err := createClient(c)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    memories, err := mem0Client.GetMemories(c.Request.Context(), userID)
    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success":  true,
        "count":    len(memories),
        "memories": memories,
    })
}

func searchMemories(c *gin.Context) {
    var req client.SearchMemoryRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    mem0Client, err := createClient(c)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    results, err := mem0Client.SearchMemories(c.Request.Context(), req)
    if err != nil {
        handleError(c, err)
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "count":   len(results),
        "results": results,
    })
}

func handleError(c *gin.Context, err error) {
    if errors.Is(err, client.ErrAccessDenied) {
        c.JSON(http.StatusForbidden, gin.H{
            "error":   "Access Denied",
            "message": err.Error(),
        })
        return
    }

    var rateLimitErr *client.RateLimitError
    if errors.As(err, &rateLimitErr) {
        c.Header("Retry-After", string(rune(rateLimitErr.RetryAfter)))
        c.JSON(http.StatusTooManyRequests, gin.H{
            "error":      "Rate Limit Exceeded",
            "message":    rateLimitErr.Message,
            "retryAfter": rateLimitErr.RetryAfter,
        })
        return
    }

    if errors.Is(err, client.ErrBadRequest) {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}
```

Run:
```bash
go run examples/gin-api/main.go
```

Test:
```bash
curl -X POST http://localhost:8080/api/memories \
  -H "Content-Type: application/json" \
  -H "X-User-Id: agent-001" \
  -H "X-User-Role: agent-writer" \
  -H "X-Tenant-Id: tenant-acme" \
  -d '{"content": "Test memory", "user_id": "alice"}'
```

---

## Error Handling

### Robust Error Handling with Retry

**`utils/retry.go`:**

```go
package utils

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/sirupsen/logrus"
    "github.com/yourorg/mem0-governance-client/client"
)

// RetryConfig configures retry behavior
type RetryConfig struct {
    MaxRetries int
    BaseDelay  time.Duration
}

// DefaultRetryConfig returns default retry configuration
func DefaultRetryConfig() RetryConfig {
    return RetryConfig{
        MaxRetries: 3,
        BaseDelay:  time.Second,
    }
}

// WithRetry executes a function with retry logic
func WithRetry(ctx context.Context, config RetryConfig, fn func() error) error {
    var lastErr error

    for attempt := 0; attempt < config.MaxRetries; attempt++ {
        err := fn()
        if err == nil {
            return nil
        }

        lastErr = err

        // Don't retry on access denied
        if errors.Is(err, client.ErrAccessDenied) {
            logrus.Errorf("Access denied: %v", err)
            return err
        }

        // Handle rate limit with specific retry delay
        var rateLimitErr *client.RateLimitError
        if errors.As(err, &rateLimitErr) {
            delay := time.Duration(rateLimitErr.RetryAfter) * time.Second
            logrus.Warnf("Rate limited. Waiting %v...", delay)

            select {
            case <-time.After(delay):
                continue
            case <-ctx.Done():
                return ctx.Err()
            }
        }

        // Handle service unavailable with exponential backoff
        if errors.Is(err, client.ErrServiceUnavailable) {
            delay := config.BaseDelay * time.Duration(1<<attempt)
            logrus.Warnf("Service unavailable. Retry %d/%d after %v...",
                attempt+1, config.MaxRetries, delay)

            select {
            case <-time.After(delay):
                continue
            case <-ctx.Done():
                return ctx.Err()
            }
        }

        // Don't retry on other errors
        return err
    }

    return fmt.Errorf("failed after %d attempts: %w", config.MaxRetries, lastErr)
}
```

**Usage:**

```go
package main

import (
    "context"
    "fmt"

    "github.com/yourorg/mem0-governance-client/client"
    "github.com/yourorg/mem0-governance-client/utils"
)

func main() {
    headers := client.GovernanceHeaders{
        UserID:   "agent-001",
        UserRole: "agent-writer",
        TenantID: "tenant-acme",
    }

    c := client.NewGovernedMem0Client("http://localhost:9000", headers)
    ctx := context.Background()

    req := client.CreateMemoryRequest{
        Messages: []client.MemoryMessage{
            {Role: "user", Content: "Test content"},
        },
        UserID: "user-alice",
    }

    var memory *client.Memory
    err := utils.WithRetry(ctx, utils.DefaultRetryConfig(), func() error {
        var err error
        memory, err = c.CreateMemory(ctx, req)
        return err
    })

    if err != nil {
        fmt.Printf("Failed: %v\n", err)
        return
    }

    fmt.Printf("Success: %s\n", memory.ID)
}
```

---

## Rate Limiting

### Batch Processing with Rate Limit Awareness

**`utils/batch.go`:**

```go
package utils

import (
    "context"
    "sync"
    "time"

    "github.com/sirupsen/logrus"
)

// BatchProcessor handles batch processing with rate limiting
type BatchProcessor[T any, R any] struct {
    BatchSize int
    Delay     time.Duration
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor[T any, R any](batchSize int, delay time.Duration) *BatchProcessor[T, R] {
    return &BatchProcessor[T, R]{
        BatchSize: batchSize,
        Delay:     delay,
    }
}

// Process processes items in batches
func (bp *BatchProcessor[T, R]) Process(
    ctx context.Context,
    items []T,
    operation func(context.Context, T) (R, error),
) ([]R, []error) {

    results := make([]R, 0, len(items))
    errors := make([]error, 0)
    var mu sync.Mutex

    totalBatches := (len(items) + bp.BatchSize - 1) / bp.BatchSize

    for i := 0; i < len(items); i += bp.BatchSize {
        end := i + bp.BatchSize
        if end > len(items) {
            end = len(items)
        }

        batch := items[i:end]
        batchNum := (i / bp.BatchSize) + 1

        logrus.Infof("Processing batch %d/%d (%d items)", batchNum, totalBatches, len(batch))

        // Process batch concurrently
        var wg sync.WaitGroup
        for _, item := range batch {
            wg.Add(1)
            go func(item T) {
                defer wg.Done()

                result, err := operation(ctx, item)

                mu.Lock()
                if err != nil {
                    errors = append(errors, err)
                } else {
                    results = append(results, result)
                }
                mu.Unlock()
            }(item)
        }

        wg.Wait()

        // Delay between batches
        if end < len(items) {
            select {
            case <-time.After(bp.Delay):
            case <-ctx.Done():
                return results, append(errors, ctx.Err())
            }
        }
    }

    return results, errors
}
```

**Usage:**

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/yourorg/mem0-governance-client/client"
    "github.com/yourorg/mem0-governance-client/utils"
)

func main() {
    headers := client.GovernanceHeaders{
        UserID:   "admin-001",
        UserRole: "admin", // Admin gets 500 req/min
        TenantID: "tenant-acme",
    }

    c := client.NewGovernedMem0Client("http://localhost:9000", headers)
    ctx := context.Background()

    // Create 100 test memories
    contents := make([]string, 100)
    for i := 0; i < 100; i++ {
        contents[i] = fmt.Sprintf("Memory %d", i)
    }

    processor := utils.NewBatchProcessor[string, *client.Memory](
        50,              // 50 per batch
        1500*time.Millisecond, // 1.5s delay
    )

    results, errors := processor.Process(ctx, contents, func(ctx context.Context, content string) (*client.Memory, error) {
        return c.CreateMemory(ctx, client.CreateMemoryRequest{
            Messages: []client.MemoryMessage{
                {Role: "user", Content: content},
            },
            UserID: "user-alice",
        })
    })

    fmt.Printf("Imported %d/%d memories\n", len(results), len(contents))
    if len(errors) > 0 {
        fmt.Printf("Errors: %d\n", len(errors))
    }
}
```

---

## Advanced Patterns

### Connection Pool Configuration

**`client/pooled_client.go`:**

```go
package client

import (
    "net"
    "net/http"
    "time"
)

// NewPooledHTTPClient creates an HTTP client with connection pooling
func NewPooledHTTPClient() *http.Client {
    transport := &http.Transport{
        Proxy: http.ProxyFromEnvironment,
        DialContext: (&net.Dialer{
            Timeout:   30 * time.Second,
            KeepAlive: 90 * time.Second,
        }).DialContext,
        MaxIdleConns:          100,
        MaxIdleConnsPerHost:   10,
        IdleConnTimeout:       90 * time.Second,
        TLSHandshakeTimeout:   10 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
    }

    return &http.Client{
        Transport: transport,
        Timeout:   30 * time.Second,
    }
}

// NewPooledGovernedMem0Client creates a client with connection pooling
func NewPooledGovernedMem0Client(gatewayURL string, headers GovernanceHeaders) *GovernedMem0Client {
    return &GovernedMem0Client{
        gatewayURL: gatewayURL,
        headers:    headers,
        httpClient: NewPooledHTTPClient(),
    }
}
```

---

## Project Structure

```
mem0-governance-client/
├── go.mod
├── go.sum
├── client/
│   ├── mem0_client.go
│   ├── multitenant.go
│   └── pooled_client.go
├── middleware/
│   └── governance.go
├── utils/
│   ├── retry.go
│   └── batch.go
└── examples/
    ├── basic/
    │   └── main.go
    ├── multitenant/
    │   └── main.go
    └── gin-api/
        └── main.go
```

---

## Next Steps

- **[Python Examples](./API_EXAMPLES.md)** - Python SDK examples
- **[JavaScript/TypeScript](./API_EXAMPLES_JAVASCRIPT.md)** - Node.js examples
- **[Java Examples](./API_EXAMPLES_JAVA.md)** - Java Spring Boot examples
- **[Common Scenarios](./COMMON_SCENARIOS.md)** - Multi-tenant, custom roles
- **[Quick Start](./QUICKSTART.md)** - Get started from scratch

---

**Need help?** [Open an issue](https://github.com/your-org/oss-governance-for-mem0/issues)
