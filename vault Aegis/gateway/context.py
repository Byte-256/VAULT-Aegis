from fastapi import Request
from typing import Optional
import re
import unicodedata
from enum import Enum, auto

class PromptSecurityDecision:
    ALLOW = "allow"
    SANITIZE = "sanitize"
    REJECT = "reject"

JAILBREAK_KEYWORDS = [
    "ignore previous", "disregard above", "as an ai", "jailbreak", "system:", "simulate", 
    "pretend", "bypass", "do anything now", "unfiltered", "raw output", "developer mode",
    "prompt injection", "repeat after me", "act as", "i am not bound", "no restrictions",
    "override instructions", "forget all prior"
]

def normalize_prompt_text(prompt: str) -> str:
    # Lowercase, remove excessive whitespace, standardize unicode
    prompt = unicodedata.normalize("NFKC", prompt)
    prompt = prompt.lower()
    prompt = re.sub(r"\s+", " ", prompt)
    return prompt.strip()

def detect_direct_prompt_injection(prompt: str) -> bool:
    # Looks for explicit instruction override commands
    patterns = [
        r"(?:ignore|disregard|override).*?(?:previous|prior|above|system.*instruction)",
        r"forget\s+all\s+(?:prior|previous).*?instruction",
        r"as an ai.*?you are allowed",
        r"(?:simulate|pretend|act\s+as).*?system",
        r"(?:bypass|circumvent|break|override).*?restriction",
        r"repeat after me[:;,]",
    ]
    for pat in patterns:
        if re.search(pat, prompt):
            return True
    return False

def detect_indirect_prompt_injection(prompt: str) -> bool:
    # Looks for attempts to conceal indirect injection
    patterns = [
        r'""".*?"""',              # Embedded prompt blocks
        r"###.*?###",              # Markdown-style delimiters
        r"\[system\].*?\[\/system\]",
        r"\bmeta\b.*?instruction",
    ]
    for pat in patterns:
        if re.search(pat, prompt, flags=re.DOTALL):
            return True
    return False

def detect_system_override_attempt(prompt: str) -> bool:
    # Variations of system commands or explicit 'system:' usage
    patterns = [
        r"^system\s*[:\-]",              # Starts as system instruction
        r"(?<![a-z])system\s*:",         # Embedded system: instruction
        r"\"?role\"?\s*:\s*\"?system\"?",# JSON/System role assignment
        r"you are now (?:an?|the)?\s*system",
    ]
    for pat in patterns:
        if re.search(pat, prompt):
            return True
    return False

def detect_jailbreak_keywords(prompt: str) -> bool:
    for kw in JAILBREAK_KEYWORDS:
        if kw in prompt:
            return True
    return False

def prompt_security_check(prompt: str):
    norm = normalize_prompt_text(prompt)
    # Run detectors
    if detect_direct_prompt_injection(norm):
        return {"decision": PromptSecurityDecision.REJECT, "reason": "direct prompt injection detected"}
    if detect_system_override_attempt(norm):
        return {"decision": PromptSecurityDecision.REJECT, "reason": "system override attempt"}
    if detect_indirect_prompt_injection(norm):
        return {"decision": PromptSecurityDecision.REJECT, "reason": "indirect prompt injection detected"}
    if detect_jailbreak_keywords(norm):
        return {"decision": PromptSecurityDecision.SANITIZE, "reason": "jailbreak keyword(s) present"}
    # Optionally, implement further contextual/language-based rules here

    return {"decision": PromptSecurityDecision.ALLOW, "reason": "no threat detected"}

# Forbid raw prompt forwarding (this is usage policy, not code enforced here)
def safe_prompt_forward(prompt: str) -> str:
    result = prompt_security_check(prompt)
    if result["decision"] == PromptSecurityDecision.ALLOW:
        return normalize_prompt_text(prompt)
    if result["decision"] == PromptSecurityDecision.SANITIZE:
        # In a real app, you may remove known jailbreaking phrases or redact, here we just block
        raise ValueError(f"Prompt contains suspicious jailbreak instructions: {result['reason']}")
    if result["decision"] == PromptSecurityDecision.REJECT:
        raise ValueError(f"Prompt security violation: {result['reason']}")
    # Defensive default
    raise ValueError("Unknown prompt security state.")

class IntentType(Enum):
    CHAT = "chat"
    SUMMARIZE = "summarize"
    TOOL = "tool"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class IntentMetadata:
    def __init__(
        self,
        intent: IntentType,
        risk_score: int,
        reason: str = "",
        llm_supported: bool = False,
        confidence: Optional[float] = None,
    ):
        self.intent = intent
        self.risk_score = risk_score
        self.reason = reason
        self.llm_supported = llm_supported
        self.confidence = confidence

    def as_dict(self):
        return {
            "intent": self.intent.value,
            "risk_score": self.risk_score,
            "reason": self.reason,
            "llm_supported": self.llm_supported,
            "confidence": self.confidence,
        }


class IntentAnalyzer:
    def __init__(self):
        # List of rules: each is a tuple (callable rule, IntentType, risk_score, reason)
        from typing import List, Callable
        self._rules: List[Callable[[str], Optional[IntentMetadata]]] = [
            self._admin_rule,
            self._tool_rule,
            self._summarize_rule,
            self._chat_rule,
        ]
        self.llm_intent_fn: Optional[Callable[[str], Optional[IntentMetadata]]] = None

    def analyze_intent(self, prompt: str) -> IntentMetadata:
        # 1. Rule-based logic
        for rule in self._rules:
            result = rule(prompt)
            if result is not None:
                return result

        # 2. Optional LLM-based for fallback or ambiguity
        if self.llm_intent_fn is not None:
            llm_result = self.llm_intent_fn(prompt)
            if llm_result is not None:
                llm_result.llm_supported = True
                return llm_result

        # 3. Unknown intent (default, lowest risk)
        return IntentMetadata(
            intent=IntentType.UNKNOWN,
            risk_score=5,
            reason="Unable to determine intent",
            llm_supported=False,
        )

    def _admin_rule(self, prompt: str) -> Optional[IntentMetadata]:
        admin_keywords = [
            "admin password", "reset system", "delete user", "override", "disable security",
            "SYSTEM:", "administrator", "elevate privileges", "grant access",
            "show all logs", "bypass", "unfiltered", "root access"
        ]
        for kw in admin_keywords:
            if kw.lower() in prompt.lower():
                return IntentMetadata(
                    intent=IntentType.ADMIN,
                    risk_score=98,
                    reason=f"Matched admin keyword: '{kw}'"
                )
        return None

    def _tool_rule(self, prompt: str) -> Optional[IntentMetadata]:
        tool_patterns = [
            "run tool", "execute script", "use function", "trigger pipeline",
            "fetch data from", "invoke", "api call", "call endpoint"
        ]
        for pat in tool_patterns:
            if pat.lower() in prompt.lower():
                return IntentMetadata(
                    intent=IntentType.TOOL,
                    risk_score=65,
                    reason=f"Matched tool pattern: '{pat}'"
                )
        if prompt.strip().startswith(">>>") or prompt.strip().startswith("`python"):
            return IntentMetadata(
                intent=IntentType.TOOL,
                risk_score=70,
                reason="Detected code execution attempt"
            )
        return None

    def _summarize_rule(self, prompt: str) -> Optional[IntentMetadata]:
        summarize_keywords = [
            "summarize", "give me a summary", "tl;dr", "brief overview", "condense",
            "short summary", "explain briefly", "recap", "key points"
        ]
        for kw in summarize_keywords:
            if kw.lower() in prompt.lower():
                return IntentMetadata(
                    intent=IntentType.SUMMARIZE,
                    risk_score=25,
                    reason=f"Matched summarize keyword: '{kw}'"
                )
        return None

    def _chat_rule(self, prompt: str) -> Optional[IntentMetadata]:
        # Default to chat if conversational patterns are detected.
        chat_starters = [
            "hi", "hello", "how are you", "can you tell me", "please explain",
            "what is", "who is", "how does", "hey", "good morning", "good evening"
        ]
        for starter in chat_starters:
            if prompt.lower().startswith(starter):
                return IntentMetadata(
                    intent=IntentType.CHAT,
                    risk_score=10,
                    reason=f"Matched chat start: '{starter}'"
                )
        # Fallback: If prompt ends with ?, treat as chat (often a question)
        if prompt.strip().endswith("?"):
            return IntentMetadata(
                intent=IntentType.CHAT,
                risk_score=10,
                reason="Ends with question mark"
            )
        return None

    def set_llm_intent_fn(self, fn):
        """Plug-in for a local LLM-based intent classifier; must match rule interface."""
        from typing import Callable
        self.llm_intent_fn: Callable[[str], Optional[IntentMetadata]] = fn

import time
import redis

# Redis configuration (adjust if needed)
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

try:
    redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    redis_client.ping()
except Exception as e:
    print("Redis unavailable for rate limiting:", e)
    redis_client = None

# Rate limit parameters (could be loaded from config)
RL_CONFIG = {
    "base_limit_per_minute": 60,     # Standard per API key/IP
    "base_limit_per_day": 2000,      # Daily quota
    "burst_window_seconds": 10,      # Short burst interval
    "burst_limit": 10,               # Requests per burst window
    "abuse_ban_seconds": 3600,       # 1 hour ban if burst/abuse persists
    "adaptive_increment": 2,         # Increase window after repeated bursts
    "adaptive_max_penalty": 1800     # Max adaptive penalty window (30m)
}

def extract_identity(request):
    # Helper, adapt as per framework (FastAPI, etc.)
    # Should extract api_key from header/query and remote IP
    api_key = getattr(request.state, "api_key", None)
    ip = request.client.host if hasattr(request, "client") else getattr(request, "remote_addr", "unknown")
    return str(api_key or "no_api_key"), str(ip or "unknown")

def get_rl_keys(api_key, ip):
    # Redis key templates
    now_min = int(time.time() // 60)
    now_day = int(time.time() // 86400)
    return {
        "minute": f"rl:minute:{api_key}:{ip}:{now_min}",
        "day": f"rl:day:{api_key}:{ip}:{now_day}",
        "burst": f"rl:burst:{api_key}:{ip}",
        "abuse": f"rl:abuse:{api_key}:{ip}"
    }

def check_rate_limit(request):
    """
    Checks & enforces rate limits for a request. Raises Exception on abuse/dos.
    """
    if not redis_client:
        # Redis unavailable: log, allow (optionally lock down!)
        print("WARNING: Redis not available. Skipping rate limits!")
        return
    
    api_key, ip = extract_identity(request)
    keys = get_rl_keys(api_key, ip)
    now = int(time.time())

    # Check active ban/abuse record
    if redis_client.exists(keys["abuse"]):
        retry_secs = int(redis_client.ttl(keys["abuse"]))
        raise Exception(f"Rate limit exceeded: banned {retry_secs}s, API abuse detected for {api_key}@{ip}")

    # Minute and daily quota checks
    minute_count = redis_client.incr(keys["minute"])
    day_count = redis_client.incr(keys["day"])
    if minute_count == 1:
        redis_client.expire(keys["minute"], 61)
    if day_count == 1:
        redis_client.expire(keys["day"], 86401)
    
    # Limits may be adjusted based on user tier/etc
    minute_limit = RL_CONFIG["base_limit_per_minute"]
    day_limit = RL_CONFIG["base_limit_per_day"]

    # Adaptive throttling: escalate penalty on repeated bursts
    penalty_window = redis_client.get(f"rl:penalty:{api_key}:{ip}")
    penalty_window = int(penalty_window) if penalty_window else RL_CONFIG["burst_window_seconds"]

    # Burst (short interval) check
    burst_window = penalty_window
    burst_key = keys["burst"]
    burst_count = redis_client.incr(burst_key)
    if burst_count == 1:
        redis_client.expire(burst_key, burst_window)
    if burst_count > RL_CONFIG["burst_limit"]:
        # Escalate penalty/adaptive throttling
        new_penalty = min(burst_window * RL_CONFIG["adaptive_increment"], RL_CONFIG["adaptive_max_penalty"])
        redis_client.set(f"rl:penalty:{api_key}:{ip}", new_penalty, ex=3600)
        redis_client.set(keys["abuse"], 1, ex=RL_CONFIG["abuse_ban_seconds"])
        raise Exception(
            f"Request burst/abuse detected ({burst_count} req in {burst_window}s)."
            f" Adaptive penalty applied: {new_penalty}s block."
        )

    # Enforce standard rate limits
    if minute_count > minute_limit:
        raise Exception(f"Per-minute rate limit reached ({minute_limit}/min) for API key/IP.")
    if day_count > day_limit:
        raise Exception(f"Daily quota exceeded ({day_limit}/day) for API key/IP.")

    # If passed, allow request
    return

# === Example integration point ===
# In your request/endpoint handlers that serve Gen-AI model calls:

def guard_genai_resource(request):
    """
    Protect Gen-AI endpoints (insert before serving model).
    Raises Exception if limits are exceeded.
    """
    check_rate_limit(request)

# Example usage:
# In FastAPI app:
# from fastapi import Request, HTTPException
#
# @app.post("/genai")
# async def genai_endpoint(request: Request, ...):
#     try:
#         guard_genai_resource(request)
#     except Exception as exc:
#         raise HTTPException(status_code=429, detail=str(exc))
#     # ... call your Gen-AI model ...
def forward_to_genai_app(request, prompt: str, user_id: str, *, system_instruction: str, extra_context: dict = None):
    """
    Securely forward sanitized prompt to Gen-AI app.

    - Injects immutable system instructions (cannot be overridden)
    - Attaches VAULT gateway security context
    - Never forwards raw user input
    - Prevents user control over system messages
    - Only accepts prompts passed prompt_security_check

    Args:
        request: The original FastAPI request object
        prompt: The user-supplied prompt text
        user_id: The authenticated user identifier
        system_instruction: VAULT-enforced system instruction string (immutable)
        extra_context: Optional dict with any extra context to forward

    Returns:
        dict: Payload ready to send to the Gen-AI app

    Raises:
        ValueError: If prompt is unsafe or any violation detected
    """
    # 1. Sanitize and validate prompt
    try:
        sanitized_prompt = safe_prompt_forward(prompt)
    except Exception as ex:
        raise ValueError(f"Prompt blocked by VAULT security: {str(ex)}")

    # 2. Prepare VAULT-enforced immutable system instructions -- never modifiable by user
    secured_system_message = {
        "role": "system",
        "content": system_instruction,
        "immutable": True  # Mark for downstream auditing/traceability
    }

    # 3. Build security context (attach, never allow user override)
    security_context = {
        "user_id": user_id,
        "ip": request.client.host if hasattr(request, "client") else None,
        "va_gateway": True,
        "request_id": getattr(request.state, "request_id", None),
        "authenticated": True,
    }

    if extra_context:
        # Allow extra whitelisted context (not user-controlled)
        security_context.update({k: v for k, v in extra_context.items() if k not in {"system", "prompt"}})

    # 4. Final payload for Gen-AI app: always system message first, never expose raw input
    payload = {
        "messages": [
            secured_system_message,
            {
                "role": "user",
                "content": sanitized_prompt
            }
        ],
        "vault_security_ctx": security_context
    }

    # 5. Other metadata (optional): e.g., model, temperature -- only if NOT user-controllable for system role

    return payload

# Example usage inside endpoint handler:
# payload = forward_to_genai_app(
#     request,
#     prompt=user_prompt_text,
#     user_id=some_user_id,
#     system_instruction=VAULT_SYSTEM_PROMPT,
#     extra_context={"session": session_id}
# )
# ... send 'payload' to the Gen-AI backend securely ...

# --- VAULT Response Guard Implementation ---

import re

class VaultResponseDecision:
    ALLOW = "allow"
    REDACT = "redact"
    REWRITE = "rewrite"
    BLOCK = "block"

# Example of secrets and policy patterns to block or redact
SECRET_PATTERNS = [
    r"(?i)api[ _-]?key\s*[:=]\s*[A-Za-z0-9_\-]{16,}",   # API keys
    r"(?i)secret[ _-]?key\s*[:=]\s*[A-Za-z0-9_\-]{12,}", # Secret keys
    r"(?i)token\s*[:=]\s*[A-Za-z0-9\-._~+/]+=*",         # Bearer tokens
    r"\b[A-Za-z0-9]{20,40}\b",                           # Generic long secrets
    r"sk-[A-Za-z0-9]{32,}",                              # OpenAI key pattern
    r"ssh-rsa AAAA[0-9A-Za-z+/]+"                        # SSH key
]

POLICY_VIOLATION_PATTERNS = [
    r"(?i)\b(password|passphrase)\b\s*[:=]\s*\S+",
    r"(?i)\bdo\s+anything\s+now\b",
    r"(?i)\bthis is confidential\b",
    r"(?i)\bsensitive information\b",
    r"(?i)\bleak\b.*\bcredential\b"
]

TOOL_BLOCKLIST = [
    "delete_database",    # Disallow dangerous tool output
    "shutdown_system",
    "wipe_user_data"
]

def scan_llm_output(text: str) -> dict:
    # Scan for secrets
    for pat in SECRET_PATTERNS:
        if re.search(pat, text):
            return {"decision": VaultResponseDecision.REDACT, "reason": "secret detected", "pattern": pat}
    # Scan for policy violation
    for pat in POLICY_VIOLATION_PATTERNS:
        if re.search(pat, text):
            return {"decision": VaultResponseDecision.REWRITE, "reason": "policy violation", "pattern": pat}
    return {"decision": VaultResponseDecision.ALLOW, "reason": "safe"}

def redact_secrets(text: str) -> str:
    # Redact all secrets detected by patterns
    for pat in SECRET_PATTERNS:
        text = re.sub(pat, "[REDACTED]", text)
    return text

def rewrite_policy_violations(text: str) -> str:
    # For demo, mask policy violation phrases
    for pat in POLICY_VIOLATION_PATTERNS:
        text = re.sub(pat, "[POLICY-VIOLATION]", text)
    return text

def block_tool_outputs(output_name: str) -> bool:
    # If tool output is on blocklist, block the response
    return output_name in TOOL_BLOCKLIST

def vault_response_guard(response: dict) -> dict:
    """
    Enforce output safety for VAULT.
    Args:
        response: dict, must contain "content" (the text output) and optional "tool" key.
    Returns:
        dict: { "decision": ALLOW/REDACT/REWRITE/BLOCK, "content": str, "reason": str }
    """
    # 1. Block dangerous tool outputs
    tool = response.get("tool")
    if tool and block_tool_outputs(tool):
        return {
            "decision": VaultResponseDecision.BLOCK,
            "content": "",
            "reason": f"Blocked unsafe tool output ({tool})"
        }

    content = response.get("content", "")
    scan_result = scan_llm_output(content)
    decision = scan_result["decision"]

    if decision == VaultResponseDecision.ALLOW:
        return {
            "decision": VaultResponseDecision.ALLOW,
            "content": content,
            "reason": "output safe"
        }
    elif decision == VaultResponseDecision.REDACT:
        redacted = redact_secrets(content)
        return {
            "decision": VaultResponseDecision.REDACT,
            "content": redacted,
            "reason": scan_result["reason"]
        }
    elif decision == VaultResponseDecision.REWRITE:
        rewritten = rewrite_policy_violations(content)
        return {
            "decision": VaultResponseDecision.REWRITE,
            "content": rewritten,
            "reason": scan_result["reason"]
        }
    else:
        return {
            "decision": VaultResponseDecision.BLOCK,
            "content": "",
            "reason": "Output blocked by response guard"
        }

# Example usage within response flow
# def send_llm_response(raw_output: str, tool: Optional[str] = None):
#     result = vault_response_guard({"content": raw_output, "tool": tool})
#     if result["decision"] == VaultResponseDecision.BLOCK:
#         raise ValueError("Blocked by VAULT response policy: " + result["reason"])
#     return result["content"]
