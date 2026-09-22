"""Tenants & agents endpoints — moved out of server.py to keep the orchestrator lean.

Routes are mounted without prefix (full paths below) via
app.include_router (see server.py). Handlers are verbatim copies of the
originals: same paths, models, auth and payloads.
"""
import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import require_auth, require_role

router = APIRouter(tags=["tenants-agents"])


class TenantCreateRequest(BaseModel):
    name: str
    domain: Optional[str] = None


@router.get("/api/v1/tenants")
def get_tenants(user: dict = Depends(require_auth)):
    from auth import list_tenants
    return {"tenants": list_tenants()}


@router.post("/api/v1/tenants")
def post_tenant(req: TenantCreateRequest, user: dict = Depends(require_role("admin"))):
    from auth import create_tenant
    tenant_id = create_tenant(req.name, req.domain)
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant already exists or invalid data")
    return {"status": "created", "tenant_id": tenant_id, "name": req.name}


class AgentTokenRequest(BaseModel):
    tenant_id: int = 1
    expires_in_seconds: int = 86400


@router.post("/api/v1/agents/tokens")
def post_agent_token(req: AgentTokenRequest, user: dict = Depends(require_role("admin"))):
    from auth import create_agent_token
    token = create_agent_token(tenant_id=req.tenant_id, expires_in_seconds=req.expires_in_seconds, created_by=user.get("id", 1))
    return {"token": token, "tenant_id": req.tenant_id, "expires_in_seconds": req.expires_in_seconds}


class AgentRegisterRequest(BaseModel):
    token: str
    agent_id: str
    name: str
    ip_address: str
    os_type: str = "windows"


@router.post("/api/v1/agents/register")
def post_agent_register(req: AgentRegisterRequest):
    from auth import register_agent
    result = register_agent(token=req.token, agent_id=req.agent_id, name=req.name, ip_address=req.ip_address, os_type=req.os_type)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")
    return result


class AgentHeartbeatRequest(BaseModel):
    agent_id: str
    agent_secret: str
    status: str = "active"
    metrics: Optional[Dict[str, Any]] = None


@router.post("/api/v1/agents/heartbeat")
def post_agent_heartbeat(req: AgentHeartbeatRequest):
    from auth import agent_heartbeat
    rules_json = json.dumps(req.metrics) if req.metrics else None
    result = agent_heartbeat(agent_id=req.agent_id, agent_secret=req.agent_secret, status_str=req.status, rules_json=rules_json)
    if not result:
        raise HTTPException(status_code=401, detail="Unknown agent or invalid agent secret")
    return result


@router.get("/api/v1/agents")
def get_agents(user: dict = Depends(require_auth), tenant_id: Optional[int] = None):
    from auth import list_agents
    return {"agents": list_agents(tenant_id=tenant_id)}
