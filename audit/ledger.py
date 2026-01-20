import hashlib
import threading
import time
from typing import Optional, Dict, Any, List

class TamperResistantLedger:
    """
    Tamper-resistant, privacy-safe ledger for audit, trust, and forensics in 
    Logs event hashes (not raw payloads), decisions, risk, intent, and tool activity.
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        # Singleton to ensure one ledger in process
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_ledger()
        return cls._instance

    def _init_ledger(self):
        self.chain = []
        self.last_hash = None

    def _hash_data(self, data: Dict[str, Any]) -> str:
        # Only hash serializable data
        msg = str(sorted(data.items())).encode("utf-8")
        return hashlib.sha256(msg).hexdigest()

    def _ledger_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        ts = time.time()
        entry_serializable = {
            "timestamp": ts,
            "type": entry.get("type", "event"),
            "request_hash": entry.get("request_hash"),
            "intent": entry.get("intent"),
            "risk": entry.get("risk"),
            "policy_decision": entry.get("policy_decision"),
            "tool": entry.get("tool"),
            "response_hash": entry.get("response_hash"),
            "details": entry.get("details"),
            "prev_hash": self.last_hash,
        }
        entry_hash = self._hash_data(entry_serializable)
        entry_serializable["entry_hash"] = entry_hash
        return entry_serializable

    def log_event(
        self,
        *,
        request_data: Optional[Any] = None,
        intent: Optional[str] = None,
        risk: Optional[Any] = None,
        policy_decision: Optional[str] = None,
        tool: Optional[str] = None,
        response_data: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None,
        event_type: str = "event",
    ):
        # Never log raw request/response -- hash only
        req_hash = self._hash_data({"request_data": str(request_data)}) if request_data is not None else None
        resp_hash = self._hash_data({"response_data": str(response_data)}) if response_data is not None else None

        entry = self._ledger_entry({
            "type": event_type,
            "request_hash": req_hash,
            "intent": intent,
            "risk": risk,
            "policy_decision": policy_decision,
            "tool": tool,
            "response_hash": resp_hash,
            "details": details,
        })
        with self._lock:
            self.chain.append(entry)
            self.last_hash = entry["entry_hash"]

    def audit_trail(self) -> List[Dict[str, Any]]:
        # Returns the current hash chain (safe for forensic review)
        return [dict(entry) for entry in self.chain]

    def verify_integrity(self) -> bool:
        # Simple chain-of-hash verification
        prev = None
        for entry in self.chain:
            expected_hash = self._hash_data({k: entry[k] for k in entry if k not in ("entry_hash",)})
            if entry["entry_hash"] != expected_hash:
                return False
            if entry["prev_hash"] != prev:
                return False
            prev = entry["entry_hash"]
        return True

# -------- Example usage hooks ----------
# These hooks can be added to critical points in request/response flow

# Example: Log before request is processed
def audit_log_request(request_obj, intent, risk, policy_decision):
    ledger = TamperResistantLedger()
    ledger.log_event(
        request_data=request_obj,
        intent=intent,
        risk=risk,
        policy_decision=policy_decision,
        event_type="request"
    )

# Example: Log tool usage and response
def audit_log_tool(tool_name, request_obj=None, response_obj=None, policy_decision=None, details=None):
    ledger = TamperResistantLedger()
    ledger.log_event(
        request_data=request_obj,
        tool=tool_name,
        response_data=response_obj,
        policy_decision=policy_decision,
        details=details,
        event_type="tool"
    )

# Example: Forensic analysis API (to be called by admins only)
def forensic_export():
    ledger = TamperResistantLedger()
    assert ledger.verify_integrity(), "Ledger integrity check failed!"
    return ledger.audit_trail()

    # INSERT_YOUR_CODE
