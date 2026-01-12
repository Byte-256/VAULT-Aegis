from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from typing import List, Optional
import jwt

# Settings and helpers (to be defined/loaded from secure config)
def get_jwt_public_key():
    # Implement secure public key retrieval for JWT validation
    raise NotImplementedError("Public key retrieval not implemented.")

def get_api_key_info(api_key: str):
    # Look up API key in secure store, return: { "scopes": [...], "roles": [...] } or None
    # DO NOT hardcode; integrate with vault/DB in production.
    return None

# Middleware Dependency
class AuthContext:
    def __init__(self, subject: str, scopes: List[str], roles: List[str], method: str):
        self.subject = subject
        self.scopes = scopes
        self.roles = roles
        self.method = method

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
http_bearer = HTTPBearer(auto_error=False)

async def authenticate_request(
    request: Request,
    api_key: Optional[str] = Depends(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Depends(http_bearer)
) -> AuthContext:
    # Try API Key Auth
    if api_key:
        info = get_api_key_info(api_key)
        if not info:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API Key",
                headers={"WWW-Authenticate": "APIKey"},
            )
        request.state.auth = AuthContext(
            subject="apikey:" + api_key[-8:],
            scopes=info.get("scopes", []),
            roles=info.get("roles", []),
            method="api_key"
        )
        return request.state.auth

    # Try JWT Auth
    if bearer:
        try:
            key = get_jwt_public_key()
            payload = jwt.decode(
                bearer.credentials,
                key,
                algorithms=["RS256"],
                options={"verify_aud": False}  # Adjust if you have audience
            )
            subject = payload.get("sub")
            scopes = payload.get("scopes", []) or payload.get("scope", "").split()
            roles = payload.get("roles", []) or payload.get("role", [])
            if subject is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="JWT missing subject")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid JWT",
                headers={"WWW-Authenticate": "Bearer"},
            )
        request.state.auth = AuthContext(
            subject=subject,
            scopes=scopes if isinstance(scopes, list) else [scopes],
            roles=roles if isinstance(roles, list) else [roles],
            method="jwt"
        )
        return request.state.auth

    # No credentials provided
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credentials missing.",
        headers={"WWW-Authenticate": "Bearer, APIKey"},
    )

# Role/Scope Guards
def require_roles(*roles_required):
    async def checker(request: Request, ctx: AuthContext = Depends(authenticate_request)):
        if not any(role in ctx.roles for role in roles_required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return ctx
    return checker

def require_scopes(*scopes_required):
    async def checker(request: Request, ctx: AuthContext = Depends(authenticate_request)):
        if not all(scope in ctx.scopes for scope in scopes_required):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing required scopes",
            )
        return ctx
    return checker

# Example usage in route (for demonstration only, not actual router code)
# @app.get("/secure-data")
# async def secure_endpoint(auth=Depends(require_roles("admin","superuser"))):
#     return {"message": f"Hello {auth.subject}"}
