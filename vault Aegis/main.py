from fastapi import FastAPI, Request, HTTPException, Depends

# Import gateway components
from vault.gateway.middleware import authenticate_request, require_roles, require_scopes, AuthContext
from vault.gateway.routing import normalize_and_validate_llm_request, LLMRequestModel
from vault.gateway.context import (
    prompt_security_check,
    safe_prompt_forward,
    IntentAnalyzer,
    IntentMetadata,
    check_rate_limit,
    guard_genai_resource,
    forward_to_genai_app,
    vault_response_guard
)

# Import policy engine
from vault.policy.engine import VaultPolicyEngine, PolicyDecision

# Import audit ledger
from vault.audit.ledger import (
    TamperResistantLedger,
    audit_log_request,
    audit_log_tool,
    forensic_export
)

# Import scanner (for runtime checks if needed)
from vault.scanner.scanner import VaultAPIScanner

app = FastAPI(
    title="VAULT - GenAI Secure API Gateway",
    description="A secure, zero-trust GenAI API Gateway enforcing policy and protecting AI requests.",
    version="0.1.0"
)

# Initialize components
intent_analyzer = IntentAnalyzer()

# Load policy engine (adjust path as needed)
try:
    policy_engine = VaultPolicyEngine("vault/config/security.yaml")
except Exception as e:
    print(f"Policy engine load failed: {e}")
    policy_engine = None

# Initialize audit ledger
audit_ledger = TamperResistantLedger()

# Example endpoint demonstrating full VAULT security flow
@app.post("/llm-endpoint")
async def llm_endpoint(
    request: Request,
    auth: AuthContext = Depends(authenticate_request),
    llm_request: LLMRequestModel = Depends(normalize_and_validate_llm_request)
):
    """
    Secure LLM endpoint with full VAULT protection:
    - Authentication & Authorization
    - Request validation & normalization
    - Prompt security check
    - Intent analysis
    - Policy enforcement
    - Rate limiting
    - Audit logging
    - Response filtering
    """
    
    try:
        # 1. Rate limiting
        guard_genai_resource(request)
        
        # 2. Prompt security check
        prompt_check = prompt_security_check(llm_request.prompt)
        if prompt_check["decision"] != "allow":
            raise HTTPException(
                status_code=400,
                detail=f"Prompt security violation: {prompt_check['reason']}"
            )
        
        # 3. Intent analysis
        intent_metadata = intent_analyzer.analyze_intent(llm_request.prompt)
        
        # 4. Policy evaluation
        if policy_engine:
            policy_decision = policy_engine.evaluate(
                intent_metadata,
                user_role=auth.roles[0] if auth.roles else "user",
                scope="external"
            )
            
            # Enforce policy
            if not policy_decision.allow_model:
                raise HTTPException(
                    status_code=403,
                    detail=f"Policy denies model access: {policy_decision.reasons}"
                )
            
            # Enforce token limit
            if llm_request.max_tokens > policy_decision.max_tokens:
                llm_request.max_tokens = policy_decision.max_tokens
        
        # 5. Audit log request
        audit_log_request(
            request_obj={"prompt": llm_request.prompt, "user": auth.subject},
            intent=intent_metadata.intent.value,
            risk=intent_metadata.risk_score,
            policy_decision=policy_decision.matched_policy if policy_engine else "default"
        )
        
        # 6. Forward to GenAI backend (sanitized)
        genai_payload = forward_to_genai_app(
            request,
            prompt=llm_request.prompt,
            user_id=auth.subject,
            system_instruction="You are a helpful AI assistant. Follow all safety guidelines.",
            extra_context={"max_tokens": llm_request.max_tokens}
        )
        
        # 7. Simulate GenAI response (replace with actual GenAI call)
        simulated_response = {
            "content": "This is a simulated safe response from the GenAI model.",
            "tool": None
        }
        
        # 8. Response guard
        guarded_response = vault_response_guard(simulated_response)
        
        # 9. Audit log response
        audit_log_tool(
            tool_name="llm_generation",
            request_obj=genai_payload,
            response_obj=guarded_response,
            policy_decision=policy_decision.matched_policy if policy_engine else "default"
        )
        
        return {
            "response": guarded_response["content"],
            "intent": intent_metadata.intent.value,
            "risk_score": intent_metadata.risk_score,
            "policy": policy_decision.matched_policy if policy_engine else "default",
            "decision": guarded_response["decision"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

# Admin endpoint for forensic export
@app.get("/admin/audit-trail")
async def get_audit_trail(auth: AuthContext = Depends(require_roles("admin"))):
    """
    Admin-only endpoint to retrieve audit trail
    """
    try:
        trail = forensic_export()
        return {
            "audit_trail": trail,
            "integrity_verified": True
        }
    except AssertionError as e:
        raise HTTPException(status_code=500, detail="Audit ledger integrity check failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error retrieving audit trail: {str(e)}")

# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "VAULT API Gateway",
        "version": "0.1.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
