"""
VAULT Aegis - Secure API Gateway Server
FastAPI server with all security layers for LLM protection.
"""

import os
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from audit.ledger import (
    audit_log_request,
    audit_log_tool,
    forensic_export,
)
from gateway.context import (
    IntentAnalyzer,
    guard_genai_resource,
    prompt_security_check,
    vault_response_guard,
)

# Security imports
from gateway.middleware import (
    AuthContext,
    authenticate_request,
    require_roles,
)
from gateway.routing import LLMRequestModel, normalize_and_validate_llm_request
from pii_sanitizer.config import SanitizeMode
from pii_sanitizer.sanitizer import PIISanitizer
from policy.engine import PolicyDecision, VaultPolicyEngine

app = FastAPI(
    title="VAULT Aegis - Secure API Gateway",
    description="AI-Native Security & Governance Layer for LLM Systems",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Initialize security components
intent_analyzer = IntentAnalyzer()
pii_sanitizer = PIISanitizer(mode=SanitizeMode.REDACT)

try:
    policy_engine = VaultPolicyEngine("config/security.yaml")
except Exception as e:
    print(f"Policy engine load failed: {e}")
    policy_engine = None


# Request model
class LLMRequest(BaseModel):
    prompt: str
    model: str = "gpt-4"
    max_tokens: int = 500
    temperature: float = 0.7


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "VAULT Aegis Gateway",
        "version": "0.1.0",
        "security_layers": [
            "rate_limiting",
            "prompt_injection_detection",
            "pii_sanitization",
            "intent_analysis",
            "policy_enforcement",
            "audit_logging",
            "response_guard",
        ],
    }


@app.post("/llm-endpoint")
async def llm_endpoint(
    request: Request,
    auth: AuthContext = Depends(authenticate_request),
    llm_request: LLMRequestModel = Depends(normalize_and_validate_llm_request),
):
    """
    Secure LLM endpoint with full VAULT protection.
    All requests must pass through every security layer.
    """

    # Layer 1: Rate Limiting
    try:
        guard_genai_resource(request)
    except Exception as e:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded: {str(e)}")

    # Layer 2: Prompt Injection Detection
    prompt_check = prompt_security_check(llm_request.prompt)
    if prompt_check["decision"] != "allow":
        audit_log_request(
            request_obj={"prompt": llm_request.prompt, "user": auth.subject},
            intent="unknown",
            risk=1.0,
            policy_decision="prompt_injection_blocked",
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Prompt security violation",
                "reason": prompt_check.get("reason", "Injection detected"),
                "decision": prompt_check["decision"],
            },
        )

    # Layer 3: PII Sanitization (Redact mode)
    pii_result = pii_sanitizer.sanitize(llm_request.prompt)
    sanitized_prompt = pii_result.sanitized_text
    pii_detected = pii_result.detections_count > 0

    # Log PII detection but continue (redaction handled)
    if pii_detected:
        print(
            f"[PII DETECTED] User: {auth.subject}, Count: {pii_result.detections_count}"
        )
        print(f"[PII DETECTED] Types: {[d.pii_type for d in pii_result.detections]}")

    # Layer 4: Intent Analysis
    intent_metadata = intent_analyzer.analyze_intent(sanitized_prompt)

    # Layer 5: Policy Enforcement
    # Determine effective user role (from request or auth)
    effective_role = getattr(llm_request, "user_role", None) or (
        auth.roles[0] if auth.roles else "guest"
    )

    policy_decision = None
    if policy_engine:
        policy_decision = policy_engine.evaluate(
            intent_metadata,
            user_role=effective_role,
            scope="external",
        )

        if not policy_decision.allow_model:
            audit_log_request(
                request_obj={"prompt": llm_request.prompt, "user": auth.subject},
                intent=intent_metadata.intent.value,
                risk=intent_metadata.risk_score,
                policy_decision=policy_decision.matched_policy,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Policy violation",
                    "reasons": policy_decision.reasons,
                    "policy": policy_decision.matched_policy,
                },
            )

        # Enforce token limit
        if llm_request.max_tokens > policy_decision.max_tokens:
            llm_request.max_tokens = policy_decision.max_tokens

    # Layer 6: Audit Logging (Request)
    audit_log_request(
        request_obj={
            "prompt": llm_request.prompt,
            "sanitized_prompt": sanitized_prompt,
            "user": auth.subject,
        },
        intent=intent_metadata.intent.value,
        risk=intent_metadata.risk_score,
        policy_decision=policy_decision.matched_policy
        if policy_decision
        else "default",
    )

    # Layer 7: Forward to LLM (simulated - replace with actual LLM call)
    # In production, call your LLM API here with sanitized_prompt
    llm_response = await call_llm(
        prompt=sanitized_prompt,
        model=llm_request.model,
        max_tokens=llm_request.max_tokens,
        temperature=llm_request.temperature,
    )

    # Layer 8: Response Guard (filter secrets from LLM response)
    guarded_response = vault_response_guard(llm_response)

    # Layer 9: Audit Logging (Response)
    audit_log_tool(
        tool_name="llm_generation",
        request_obj={"prompt": sanitized_prompt},
        response_obj=guarded_response,
        policy_decision=policy_decision.matched_policy
        if policy_decision
        else "default",
    )

    # Return complete security analysis with response
    return {
        "response": guarded_response["content"],
        "security": {
            "intent": intent_metadata.intent.value,
            "risk_score": intent_metadata.risk_score,
            "policy": policy_decision.matched_policy if policy_decision else "default",
            "decision": guarded_response["decision"],
            "pii": {
                "detected": pii_detected,
                "count": pii_result.detections_count,
                "types": [d.pii_type for d in pii_result.detections],
                "original_length": len(llm_request.prompt),
                "sanitized_length": len(sanitized_prompt),
            },
            "prompt_check": {
                "decision": prompt_check["decision"],
                "is_injection": prompt_check.get("is_injection", False),
            },
        },
    }


async def call_llm(prompt: str, model: str, max_tokens: int, temperature: float):
    """
    Call your LLM API here.
    Replace this with actual LLM integration (OpenAI, Anthropic, local LLM, etc.)
    """
    import requests

    # Try LM Studio first (local LLM)
    # lm_studio_url = os.environ.get("LM_STUDIO_URL", "http://localhost:1234/v1")
    lm_studio_url = os.environ.get("LM_STUDIO_URL", "http://192.168.29.218:1234/v1")

    try:
        response = requests.post(
            f"{lm_studio_url}/chat/completions",
            json={
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a helpful AI assistant. Follow all safety guidelines.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
            timeout=60,
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "content": data["choices"][0]["message"]["content"],
                "model": model,
                "tool": None,
            }
        else:
            print(f"LLM API error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"LLM call failed: {e}")

    # Fallback: Generate a contextual response based on prompt analysis
    prompt_lower = prompt.lower()

    if any(word in prompt_lower for word in ["hello", "hi", "hey"]):
        content = "Hello! I'm your AI assistant, protected by VAULT Aegis security. How can I help you today?"
    elif any(word in prompt_lower for word in ["how are", "how's"]):
        content = "I'm doing well, thank you for asking! I'm running securely through VAULT Aegis. What would you like to chat about?"
    elif any(word in prompt_lower for word in ["name", "who are you"]):
        content = "I'm an AI assistant running behind VAULT Aegis security layers. I'm designed to be helpful while staying safe!"
    elif any(word in prompt_lower for word in ["weather"]):
        content = "I don't have access to real-time weather data, but I'd be happy to help with something else!"
    elif any(word in prompt_lower for word in ["help", "what can you"]):
        content = "I can help you with many tasks! Just send me a message and VAULT Aegis will process it securely. My capabilities include answering questions, having conversations, and more - all protected by security layers."
    else:
        content = f"I received your message: '{prompt[:100]}...'. This response is generated through VAULT Aegis secure gateway. The system processed your request safely with full security monitoring."

    return {
        "content": content,
        "model": model,
        "tool": None,
    }


@app.get("/admin/audit-trail")
async def get_audit_trail(auth: AuthContext = Depends(require_roles("admin"))):
    """Admin-only endpoint to retrieve audit trail."""
    try:
        trail = forensic_export()
        return {"audit_trail": trail, "integrity_verified": True}
    except AssertionError as e:
        raise HTTPException(
            status_code=500, detail="Audit ledger integrity check failed"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error retrieving audit trail: {str(e)}"
        )


@app.get("/admin/stats")
async def get_stats(auth: AuthContext = Depends(require_roles("admin"))):
    """Get security statistics."""
    try:
        trail = forensic_export()
        total = len(trail)
        high_risk = sum(1 for e in trail if (e.get("risk") or 0) >= 0.7)
        pii_count = sum(1 for e in trail if "pii" in str(e.get("details", "")).lower())

        return {
            "total_requests": total,
            "high_risk_requests": high_risk,
            "pii_detections": pii_count,
            "blocked_requests": sum(
                1
                for e in trail
                if "blocked" in str(e.get("policy_decision", "")).lower()
            ),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    print("=" * 50)
    print("VAULT Aegis - Secure API Gateway")
    print("=" * 50)
    print("Starting server on http://0.0.0.0:8000")
    print("Docs available at http://localhost:8000/docs")
    print("=" * 50)

    uvicorn.run(app, host="0.0.0.0", port=8000)
