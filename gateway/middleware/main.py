from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import httpx
import psycopg2
import os
import json
from datetime import datetime

app = FastAPI(title="Mem0 Governance Gateway")

# Configuration
OPA_URL = os.getenv("OPA_URL", "http://opa:8181/v1/data/mem0/authz/allow")
MEM0_URL = os.getenv("MEM0_URL", "http://mem0:8000")
DB_HOST = os.getenv("DB_HOST", "audit-db")
DB_NAME = os.getenv("DB_NAME", "audit")
DB_USER = os.getenv("DB_USER", "audit")
DB_PASS = os.getenv("DB_PASS", "audit")

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

def log_audit(actor_id: str, actor_role: str, tenant_id: str, 
              action: str, resource_id: str, decision: str, source_ip: str):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO mem0_audit_log 
            (actor_id, actor_role, tenant_id, action, resource_id, decision, source_ip)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (actor_id, actor_role, tenant_id, action, resource_id, decision, source_ip))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Audit log error: {e}")

def get_action_from_method(method: str, path: str) -> str:
    if method == "GET":
        return "read"
    elif method in ["POST", "PUT", "PATCH"]:
        return "write"
    elif method == "DELETE":
        return "delete"
    return "unknown"

async def check_opa(input_data: dict) -> bool:
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(OPA_URL, json={"input": input_data})
            result = response.json()
            return result.get("result", False)
        except Exception as e:
            print(f"OPA check error: {e}")
            return False

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(request: Request, path: str):
    # Extract user info from headers (set by Keycloak/OAuth proxy)
    actor_id = request.headers.get("X-User-Id", request.headers.get("X-Forwarded-User", "anonymous"))
    actor_role = request.headers.get("X-User-Role", "anonymous")
    tenant_id = request.headers.get("X-Tenant-Id", "default")
    source_ip = request.client.host if request.client else "unknown"
    
    # Determine action from HTTP method
    action = get_action_from_method(request.method, path)
    resource_id = path or "root"
    
    # Build OPA input
    opa_input = {
        "action": action,
        "roles": [actor_role],
        "tenant": tenant_id,
        "resource_tenant": tenant_id,
        "resource": resource_id
    }
    
    # Check authorization with OPA
    allowed = await check_opa(opa_input)
    decision = "allow" if allowed else "deny"
    
    # Log to audit database
    log_audit(actor_id, actor_role, tenant_id, action, resource_id, decision, source_ip)
    
    if not allowed:
        return JSONResponse(
            status_code=403,
            content={"error": "Access denied", "decision_id": resource_id}
        )
    
    # Proxy request to Mem0
    async with httpx.AsyncClient() as client:
        try:
            # Forward the request
            body = await request.body()
            headers = dict(request.headers)
            headers.pop("host", None)
            
            response = await client.request(
                method=request.method,
                url=f"{MEM0_URL}/{path}",
                headers=headers,
                content=body,
                params=request.query_params
            )
            
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
        except httpx.ConnectError:
            return JSONResponse(
                status_code=503,
                content={"error": "Backend service unavailable"}
            )
        except Exception as e:
            return JSONResponse(
                status_code=500,
                content={"error": str(e)}
            )

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
