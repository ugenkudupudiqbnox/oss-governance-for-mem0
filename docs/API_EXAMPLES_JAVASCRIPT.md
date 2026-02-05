# API Usage Examples - JavaScript/TypeScript

Complete guide for using the governed Mem0 API with JavaScript and TypeScript.

---

## Table of Contents

- [Installation](#installation)
- [TypeScript Client Library](#typescript-client-library)
- [Basic Operations](#basic-operations)
- [Multi-Tenant Operations](#multi-tenant-operations)
- [Express.js Middleware](#expressjs-middleware)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)
- [Advanced Patterns](#advanced-patterns)

---

## Installation

### Using npm

```bash
npm install axios
npm install --save-dev @types/node
```

### Using TypeScript

```bash
npm install typescript ts-node @types/node
npm install axios
```

**tsconfig.json:**
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true
  }
}
```

---

## TypeScript Client Library

### Complete TypeScript Client

**`mem0-client.ts`:**

```typescript
import axios, { AxiosInstance, AxiosError } from 'axios';

/**
 * Governance headers required for all requests
 */
export interface GovernanceHeaders {
  userId: string;      // X-User-Id
  userRole: string;    // X-User-Role (admin, agent-writer, agent-reader, auditor)
  tenantId: string;    // X-Tenant-Id
}

/**
 * Memory message structure
 */
export interface MemoryMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

/**
 * Memory creation request
 */
export interface CreateMemoryRequest {
  messages: MemoryMessage[];
  user_id: string;
  metadata?: Record<string, any>;
}

/**
 * Memory object
 */
export interface Memory {
  id: string;
  content: string;
  user_id: string;
  created_at: string;
  metadata?: Record<string, any>;
}

/**
 * Memory search request
 */
export interface SearchMemoryRequest {
  query: string;
  user_id: string;
  limit?: number;
}

/**
 * API error response
 */
export interface ApiError {
  detail: string;
}

/**
 * Rate limit error with retry information
 */
export class RateLimitError extends Error {
  retryAfter: number;

  constructor(message: string, retryAfter: number) {
    super(message);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
  }
}

/**
 * Access denied error
 */
export class AccessDeniedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AccessDeniedError';
  }
}

/**
 * Governed Mem0 API Client
 */
export class GovernedMem0Client {
  private client: AxiosInstance;
  private headers: GovernanceHeaders;

  constructor(gatewayUrl: string, headers: GovernanceHeaders) {
    this.headers = headers;
    this.client = axios.create({
      baseURL: gatewayUrl,
      headers: {
        'X-User-Id': headers.userId,
        'X-User-Role': headers.userRole,
        'X-Tenant-Id': headers.tenantId,
      },
      timeout: 10000,
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError<ApiError>) => {
        return this.handleError(error);
      }
    );
  }

  /**
   * Handle API errors with specific error types
   */
  private handleError(error: AxiosError<ApiError>): Promise<never> {
    if (error.response) {
      const status = error.response.status;
      const detail = error.response.data?.detail || 'Unknown error';

      if (status === 403) {
        return Promise.reject(new AccessDeniedError(detail));
      }

      if (status === 429) {
        const retryAfter = parseInt(
          error.response.headers['retry-after'] || '60',
          10
        );
        return Promise.reject(
          new RateLimitError(detail, retryAfter)
        );
      }

      if (status === 400) {
        return Promise.reject(
          new Error(`Bad Request: ${detail}`)
        );
      }

      if (status === 503) {
        return Promise.reject(
          new Error('Service temporarily unavailable')
        );
      }
    }

    return Promise.reject(error);
  }

  /**
   * Create a new memory
   */
  async createMemory(request: CreateMemoryRequest): Promise<Memory> {
    const response = await this.client.post<Memory>('/memories', request, {
      headers: { 'Content-Type': 'application/json' },
    });
    return response.data;
  }

  /**
   * Get all memories for a user
   */
  async getMemories(userId: string): Promise<Memory[]> {
    const response = await this.client.get<{ memories: Memory[] }>(
      '/memories',
      { params: { user_id: userId } }
    );
    return response.data.memories || [];
  }

  /**
   * Search memories
   */
  async searchMemories(request: SearchMemoryRequest): Promise<Memory[]> {
    const response = await this.client.post<{ results: Memory[] }>(
      '/memories/search',
      request,
      { headers: { 'Content-Type': 'application/json' } }
    );
    return response.data.results || [];
  }

  /**
   * Delete a memory (admin only)
   */
  async deleteMemory(memoryId: string): Promise<void> {
    await this.client.delete(`/memories/${memoryId}`);
  }

  /**
   * Get current governance context
   */
  getContext(): GovernanceHeaders {
    return { ...this.headers };
  }
}
```

---

## Basic Operations

### Create and Retrieve Memories (TypeScript)

```typescript
import { GovernedMem0Client } from './mem0-client';

async function basicExample() {
  // Initialize client
  const client = new GovernedMem0Client('http://localhost:9000', {
    userId: 'agent-001',
    userRole: 'agent-writer',
    tenantId: 'tenant-acme',
  });

  try {
    // Create a memory
    const memory = await client.createMemory({
      messages: [
        {
          role: 'user',
          content: 'My favorite programming language is TypeScript',
        },
      ],
      user_id: 'user-alice',
    });
    console.log('Created memory:', memory.id);

    // Retrieve memories
    const memories = await client.getMemories('user-alice');
    console.log(`Found ${memories.length} memories`);
    memories.forEach((m) => {
      console.log(`- ${m.content}`);
    });

    // Search memories
    const results = await client.searchMemories({
      query: 'programming language',
      user_id: 'user-alice',
    });
    console.log(`Search found ${results.length} results`);

  } catch (error) {
    console.error('Error:', error);
  }
}

basicExample();
```

### Using JavaScript (Node.js with CommonJS)

```javascript
const axios = require('axios');

const GATEWAY_URL = 'http://localhost:9000';

/**
 * Create a memory
 */
async function createMemory(userId, content, actorId, tenantId, role) {
  const response = await axios.post(
    `${GATEWAY_URL}/memories`,
    {
      messages: [{ role: 'user', content }],
      user_id: userId,
    },
    {
      headers: {
        'Content-Type': 'application/json',
        'X-User-Id': actorId,
        'X-User-Role': role,
        'X-Tenant-Id': tenantId,
      },
    }
  );
  return response.data;
}

/**
 * Get memories
 */
async function getMemories(userId, actorId, tenantId, role) {
  const response = await axios.get(`${GATEWAY_URL}/memories`, {
    params: { user_id: userId },
    headers: {
      'X-User-Id': actorId,
      'X-User-Role': role,
      'X-Tenant-Id': tenantId,
    },
  });
  return response.data.memories || [];
}

// Usage
(async () => {
  try {
    const memory = await createMemory(
      'user-alice',
      'I prefer dark mode for my IDE',
      'agent-001',
      'tenant-acme',
      'agent-writer'
    );
    console.log('Created memory:', memory.id);

    const memories = await getMemories(
      'user-alice',
      'agent-001',
      'tenant-acme',
      'agent-reader'
    );
    console.log(`Found ${memories.length} memories`);
  } catch (error) {
    console.error('Error:', error.message);
  }
})();
```

### Using Fetch API (Browser/Deno)

```typescript
interface CreateMemoryOptions {
  userId: string;
  content: string;
  actorId: string;
  tenantId: string;
  role: string;
}

async function createMemory(options: CreateMemoryOptions): Promise<any> {
  const response = await fetch('http://localhost:9000/memories', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-User-Id': options.actorId,
      'X-User-Role': options.role,
      'X-Tenant-Id': options.tenantId,
    },
    body: JSON.stringify({
      messages: [{ role: 'user', content: options.content }],
      user_id: options.userId,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Request failed');
  }

  return response.json();
}

// Usage
createMemory({
  userId: 'user-alice',
  content: 'I prefer TypeScript over JavaScript',
  actorId: 'agent-001',
  tenantId: 'tenant-acme',
  role: 'agent-writer',
}).then((memory) => console.log('Created:', memory.id));
```

---

## Multi-Tenant Operations

### TypeScript Multi-Tenant Client

```typescript
import { GovernedMem0Client, GovernanceHeaders } from './mem0-client';

/**
 * Multi-tenant memory manager
 */
export class MultiTenantMemoryManager {
  private clients: Map<string, GovernedMem0Client>;
  private gatewayUrl: string;

  constructor(gatewayUrl: string) {
    this.gatewayUrl = gatewayUrl;
    this.clients = new Map();
  }

  /**
   * Get or create a client for a specific tenant
   */
  getTenantClient(tenantId: string, userId: string, role: string): GovernedMem0Client {
    const key = `${tenantId}:${userId}:${role}`;

    if (!this.clients.has(key)) {
      const client = new GovernedMem0Client(this.gatewayUrl, {
        userId,
        userRole: role,
        tenantId,
      });
      this.clients.set(key, client);
    }

    return this.clients.get(key)!;
  }

  /**
   * Create memory for specific tenant
   */
  async createTenantMemory(
    tenantId: string,
    userId: string,
    actorId: string,
    content: string
  ): Promise<any> {
    const client = this.getTenantClient(tenantId, actorId, 'agent-writer');
    return client.createMemory({
      messages: [{ role: 'user', content }],
      user_id: userId,
    });
  }

  /**
   * Get memories for specific tenant
   */
  async getTenantMemories(
    tenantId: string,
    userId: string,
    actorId: string
  ): Promise<any[]> {
    const client = this.getTenantClient(tenantId, actorId, 'agent-reader');
    return client.getMemories(userId);
  }
}

// Usage example
async function multiTenantExample() {
  const manager = new MultiTenantMemoryManager('http://localhost:9000');

  // Tenant ACME
  await manager.createTenantMemory(
    'tenant-acme',
    'user-alice',
    'agent-acme-1',
    'ACME Corp confidential data'
  );

  // Tenant Globex (isolated from ACME)
  await manager.createTenantMemory(
    'tenant-globex',
    'user-bob',
    'agent-globex-1',
    'Globex Inc confidential data'
  );

  // Retrieve ACME memories (only returns ACME data)
  const acmeMemories = await manager.getTenantMemories(
    'tenant-acme',
    'user-alice',
    'agent-acme-1'
  );
  console.log('ACME memories:', acmeMemories.length);

  // Cross-tenant access is automatically blocked by gateway
  try {
    const client = manager.getTenantClient(
      'tenant-globex',
      'agent-globex-1',
      'agent-reader'
    );
    // This will fail with 403 Forbidden
    await client.getMemories('user-alice'); // Alice belongs to ACME
  } catch (error) {
    console.log('Cross-tenant access blocked:', error.message);
  }
}

multiTenantExample();
```

---

## Express.js Middleware

### Governance Middleware for Express

```typescript
import { Request, Response, NextFunction } from 'express';
import { GovernedMem0Client, AccessDeniedError, RateLimitError } from './mem0-client';

/**
 * Extend Express Request with governance context
 */
declare global {
  namespace Express {
    interface Request {
      mem0Client?: GovernedMem0Client;
      governance?: {
        userId: string;
        userRole: string;
        tenantId: string;
      };
    }
  }
}

/**
 * Governance middleware - extracts headers and creates Mem0 client
 */
export function governanceMiddleware(gatewayUrl: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const userId = req.headers['x-user-id'] as string;
    const userRole = req.headers['x-user-role'] as string;
    const tenantId = req.headers['x-tenant-id'] as string;

    // Validate required headers
    if (!userId || !userRole || !tenantId) {
      return res.status(400).json({
        error: 'Missing required governance headers',
        required: ['x-user-id', 'x-user-role', 'x-tenant-id'],
      });
    }

    // Create governed Mem0 client for this request
    req.mem0Client = new GovernedMem0Client(gatewayUrl, {
      userId,
      userRole,
      tenantId,
    });

    req.governance = { userId, userRole, tenantId };

    next();
  };
}

/**
 * Error handling middleware for Mem0 operations
 */
export function mem0ErrorHandler(
  err: Error,
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (err instanceof AccessDeniedError) {
    return res.status(403).json({
      error: 'Access Denied',
      message: err.message,
    });
  }

  if (err instanceof RateLimitError) {
    return res
      .status(429)
      .header('Retry-After', err.retryAfter.toString())
      .json({
        error: 'Rate Limit Exceeded',
        message: err.message,
        retryAfter: err.retryAfter,
      });
  }

  // Default error
  console.error('Mem0 Error:', err);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
}
```

### Express App Example

```typescript
import express from 'express';
import { governanceMiddleware, mem0ErrorHandler } from './governance-middleware';

const app = express();
const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:9000';

app.use(express.json());
app.use(governanceMiddleware(GATEWAY_URL));

/**
 * Create a memory
 */
app.post('/api/memories', async (req, res, next) => {
  try {
    const { content, user_id } = req.body;

    const memory = await req.mem0Client!.createMemory({
      messages: [{ role: 'user', content }],
      user_id,
    });

    res.json({
      success: true,
      memory,
      governance: req.governance,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Get memories
 */
app.get('/api/memories/:userId', async (req, res, next) => {
  try {
    const { userId } = req.params;
    const memories = await req.mem0Client!.getMemories(userId);

    res.json({
      success: true,
      count: memories.length,
      memories,
    });
  } catch (error) {
    next(error);
  }
});

/**
 * Search memories
 */
app.post('/api/memories/search', async (req, res, next) => {
  try {
    const { query, user_id } = req.body;
    const results = await req.mem0Client!.searchMemories({ query, user_id });

    res.json({
      success: true,
      count: results.length,
      results,
    });
  } catch (error) {
    next(error);
  }
});

// Error handler must be last
app.use(mem0ErrorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Gateway URL: ${GATEWAY_URL}`);
});
```

### Testing the Express App

```bash
# Start the Express server
npm run dev

# Create a memory
curl -X POST http://localhost:3000/api/memories \
  -H "Content-Type: application/json" \
  -H "x-user-id: agent-001" \
  -H "x-user-role: agent-writer" \
  -H "x-tenant-id: tenant-acme" \
  -d '{"content": "Test memory", "user_id": "alice"}'

# Get memories
curl http://localhost:3000/api/memories/alice \
  -H "x-user-id: agent-001" \
  -H "x-user-role: agent-reader" \
  -H "x-tenant-id: tenant-acme"
```

---

## Error Handling

### Comprehensive Error Handling (TypeScript)

```typescript
import {
  GovernedMem0Client,
  AccessDeniedError,
  RateLimitError,
} from './mem0-client';

async function robustMemoryOperation() {
  const client = new GovernedMem0Client('http://localhost:9000', {
    userId: 'agent-001',
    userRole: 'agent-writer',
    tenantId: 'tenant-acme',
  });

  const maxRetries = 3;
  let attempt = 0;

  while (attempt < maxRetries) {
    try {
      const memory = await client.createMemory({
        messages: [{ role: 'user', content: 'Test content' }],
        user_id: 'user-alice',
      });

      console.log('Success:', memory.id);
      return memory;

    } catch (error) {
      attempt++;

      if (error instanceof AccessDeniedError) {
        console.error('Access denied:', error.message);
        return null; // Don't retry on permission errors

      } else if (error instanceof RateLimitError) {
        console.log(`Rate limited. Waiting ${error.retryAfter}s...`);
        await sleep(error.retryAfter * 1000);
        continue; // Retry after waiting

      } else if (error.message.includes('Service temporarily unavailable')) {
        console.log(`Service unavailable. Retry ${attempt}/${maxRetries}...`);
        await sleep(5000);
        continue; // Retry

      } else if (error.message.includes('Bad Request')) {
        console.error('Bad request:', error.message);
        return null; // Don't retry on validation errors

      } else {
        console.error('Unexpected error:', error);
        if (attempt >= maxRetries) {
          throw error;
        }
        await sleep(2000);
      }
    }
  }

  console.error(`Failed after ${maxRetries} attempts`);
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
```

---

## Rate Limiting

### Handling Rate Limits with Retry

```typescript
import { GovernedMem0Client, RateLimitError } from './mem0-client';

/**
 * Retry wrapper with exponential backoff
 */
async function withRetry<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3
): Promise<T> {
  let lastError: Error;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await operation();

    } catch (error) {
      lastError = error as Error;

      if (error instanceof RateLimitError) {
        const delay = error.retryAfter * 1000;
        console.log(`Rate limited. Retrying in ${error.retryAfter}s...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }

      // Not a rate limit error, throw immediately
      throw error;
    }
  }

  throw lastError!;
}

// Usage
async function batchOperations() {
  const client = new GovernedMem0Client('http://localhost:9000', {
    userId: 'agent-001',
    userRole: 'agent-writer',
    tenantId: 'tenant-acme',
  });

  const contents = [
    'First memory',
    'Second memory',
    'Third memory',
  ];

  for (const content of contents) {
    try {
      const memory = await withRetry(() =>
        client.createMemory({
          messages: [{ role: 'user', content }],
          user_id: 'user-alice',
        })
      );
      console.log('Created:', memory.id);
    } catch (error) {
      console.error('Failed:', error.message);
    }
  }
}
```

### Rate Limit-Aware Batch Processing

```typescript
/**
 * Process items with rate limit awareness
 */
async function rateLimitedBatch<T, R>(
  items: T[],
  operation: (item: T) => Promise<R>,
  batchSize: number = 10,
  delayMs: number = 1000
): Promise<R[]> {
  const results: R[] = [];

  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);

    console.log(`Processing batch ${i / batchSize + 1}...`);

    const batchPromises = batch.map((item) =>
      withRetry(() => operation(item))
    );

    const batchResults = await Promise.allSettled(batchPromises);

    batchResults.forEach((result, idx) => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        console.error(`Item ${i + idx} failed:`, result.reason.message);
      }
    });

    // Delay between batches to respect rate limits
    if (i + batchSize < items.length) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  return results;
}

// Usage
async function bulkImport() {
  const client = new GovernedMem0Client('http://localhost:9000', {
    userId: 'admin-001',
    userRole: 'admin', // Admin gets 500 req/min
    tenantId: 'tenant-acme',
  });

  const memories = Array.from({ length: 100 }, (_, i) => ({
    content: `Memory ${i}`,
    userId: 'user-alice',
  }));

  const results = await rateLimitedBatch(
    memories,
    (memory) =>
      client.createMemory({
        messages: [{ role: 'user', content: memory.content }],
        user_id: memory.userId,
      }),
    50, // 50 per batch
    1500 // 1.5s delay between batches
  );

  console.log(`Imported ${results.length}/${memories.length} memories`);
}
```

---

## Advanced Patterns

### Connection Pooling with Axios

```typescript
import axios, { AxiosInstance } from 'axios';
import { Agent as HttpAgent } from 'http';
import { Agent as HttpsAgent } from 'https';

/**
 * Create Mem0 client with connection pooling
 */
export function createPooledClient(gatewayUrl: string) {
  const httpAgent = new HttpAgent({
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
  });

  const httpsAgent = new HttpsAgent({
    keepAlive: true,
    maxSockets: 50,
    maxFreeSockets: 10,
  });

  return axios.create({
    baseURL: gatewayUrl,
    httpAgent,
    httpsAgent,
    timeout: 10000,
  });
}
```

### Async Iterator for Pagination

```typescript
/**
 * Async iterator for paginated memory retrieval
 */
async function* getMemoriesPaginated(
  client: GovernedMem0Client,
  userId: string,
  pageSize: number = 100
): AsyncGenerator<Memory[], void, unknown> {
  let offset = 0;
  let hasMore = true;

  while (hasMore) {
    const memories = await client.getMemories(userId);

    if (memories.length === 0) {
      hasMore = false;
      break;
    }

    yield memories.slice(offset, offset + pageSize);
    offset += pageSize;

    if (offset >= memories.length) {
      hasMore = false;
    }
  }
}

// Usage
async function processAllMemories() {
  const client = new GovernedMem0Client('http://localhost:9000', {
    userId: 'agent-001',
    userRole: 'agent-reader',
    tenantId: 'tenant-acme',
  });

  for await (const memoryBatch of getMemoriesPaginated(client, 'user-alice')) {
    console.log(`Processing ${memoryBatch.length} memories...`);
    // Process batch
  }
}
```

---

## Package.json Example

```json
{
  "name": "mem0-governance-client",
  "version": "1.0.0",
  "description": "Client for governed Mem0 API",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": {
    "build": "tsc",
    "dev": "ts-node src/index.ts",
    "test": "jest",
    "lint": "eslint src/**/*.ts"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "@types/express": "^4.17.0",
    "@types/node": "^20.0.0",
    "typescript": "^5.3.0",
    "ts-node": "^10.9.0",
    "@typescript-eslint/eslint-plugin": "^6.0.0",
    "@typescript-eslint/parser": "^6.0.0",
    "eslint": "^8.0.0"
  }
}
```

---

## Next Steps

- **[Python Examples](./API_EXAMPLES.md)** - Python SDK examples
- **[Common Scenarios](./COMMON_SCENARIOS.md)** - Multi-tenant, custom roles
- **[Troubleshooting](./TROUBLESHOOTING.md)** - Debug issues
- **[Quick Start](./QUICKSTART.md)** - Get started from scratch

---

**Need help?** [Open an issue](https://github.com/your-org/oss-governance-for-mem0/issues)
