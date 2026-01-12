from fastapi import Request, HTTPException
from pydantic import BaseModel, ValidationError
import json
import re

# Helper: Remove hidden/non-printable characters except newlines and tabs
def remove_hidden_chars(s: str) -> str:
    return re.sub(r'[^\x09\x0A\x0D\x20-\x7E]', '', s)

# Example JSON schema for LLM requests
class LLMRequestModel(BaseModel):
    prompt: str
    max_tokens: int = 256
    temperature: float = 0.7

MAX_REQUEST_SIZE = 128 * 1024  # 128 KB
MAX_TOKEN_LIMIT = 4096

async def normalize_and_validate_llm_request(request: Request):
    # 1. Size limit
    raw_body = await request.body()
    if len(raw_body) > MAX_REQUEST_SIZE:
        raise HTTPException(
            status_code=413,
            detail="Request too large"
        )
    
    # 2. Decode and remove hidden chars
    try:
        decoded = raw_body.decode('utf-8')
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Request body decoding error"
        )
    cleaned = remove_hidden_chars(decoded)
    
    # 3. Parse JSON
    try:
        payload = json.loads(cleaned)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Malformed JSON in request body"
        )
    
    # 4. Validate with Pydantic schema
    try:
        obj = LLMRequestModel(**payload)
    except ValidationError as e:
        raise HTTPException(
            status_code=422,
            detail=f"JSON validation error: {e.errors()}"
        )
    
    # 5. Enforce token limit
    if hasattr(obj, "max_tokens") and obj.max_tokens > MAX_TOKEN_LIMIT:
        raise HTTPException(
            status_code=400,
            detail=f"max_tokens exceeds allowed limit of {MAX_TOKEN_LIMIT}"
        )
    
    # Attach normalized/validated payload for downstream access
    request.state.normalized_payload = obj
    return obj

# Example usage:
# @app.post("/llm-endpoint")
# async def llm_endpoint(auth=Depends(authenticate_request), req=Depends(normalize_and_validate_llm_request)):
#     # req is a validated LLMRequestModel object
#     ...
