import yaml
import json
from typing import Dict, Any


class PolicyDecision:
    def __init__(
        self,
        allow_tool: bool = False,
        allow_model: bool = False,
        allow_memory: bool = False,
        max_tokens: int = 0,
        reasons=None,
        matched_policy: str = "",
    ):
        self.allow_tool = allow_tool
        self.allow_model = allow_model
        self.allow_memory = allow_memory
        self.max_tokens = max_tokens
        self.reasons = reasons if reasons is not None else []
        self.matched_policy = matched_policy

    def as_dict(self):
        return {
            "allow_tool": self.allow_tool,
            "allow_model": self.allow_model,
            "allow_memory": self.allow_memory,
            "max_tokens": self.max_tokens,
            "reasons": self.reasons,
            "matched_policy": self.matched_policy,
        }


class VaultPolicyEngine:
    def __init__(self, policy_path):
        self.policy_path = policy_path
        self.policies = self.load_policies(policy_path)

    def load_policies(self, policy_path):
        # Support YAML or JSON by file extension
        if policy_path.lower().endswith(".yaml") or policy_path.lower().endswith(
            ".yml"
        ):
            with open(policy_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        elif policy_path.lower().endswith(".json"):
            with open(policy_path, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            raise ValueError("Policy format not supported. Use YAML or JSON.")

    def evaluate(
        self, intent_metadata, user_role: str = "user", scope: str = "default"
    ) -> PolicyDecision:
        """
        intent_metadata: IntentMetadata -- intent + risk info
        user_role: e.g. "user", "admin", etc.
        scope: e.g. "internal", "external", etc.
        """

        matched_policy = None
        reasons = []
        allow_tool = False
        allow_model = True  # Generally true unless explicitly denied
        allow_memory = False
        max_tokens = None  # Will be set by policies or default

        for policy in self.policies.get("policies", []):
            # Policy selectors: Use intent/risk/role/scope match conditions
            intent_match = (
                policy.get("intent") is None
                or policy.get("intent") == intent_metadata.intent.value
            )
            role_match = policy.get("role") is None or policy.get("role") == user_role
            scope_match = policy.get("scope") is None or policy.get("scope") == scope
            risk_min = policy.get("risk_min", 0)
            risk_max = policy.get("risk_max", 100)
            risk_match = risk_min <= intent_metadata.risk_score <= risk_max

            if intent_match and role_match and scope_match and risk_match:
                # Applies! Build decision
                allow_tool = bool(policy.get("allow_tool", allow_tool))
                allow_model = bool(policy.get("allow_model", allow_model))
                allow_memory = bool(policy.get("allow_memory", allow_memory))
                policy_max_tokens = policy.get("max_tokens")
                if policy_max_tokens is not None:
                    max_tokens = (
                        min(max_tokens, policy_max_tokens)
                        if max_tokens is not None
                        else policy_max_tokens
                    )
                matched_policy = policy.get("name", "unnamed_policy")
                reasons.append(f"Matched policy: {matched_policy}")
                # If the policy says 'terminal': true, stop further evaluation (allow most-specific/override)
                if policy.get("terminal", False):
                    break

        if not matched_policy:
            reasons.append("No specific policy matched. Defaults applied.")

        # Set default max_tokens if none was set by policies
        if max_tokens is None:
            max_tokens = 1024

        return PolicyDecision(
            allow_tool=allow_tool,
            allow_model=allow_model,
            allow_memory=allow_memory,
            max_tokens=max_tokens,
            reasons=reasons,
            matched_policy=matched_policy or "default",
        )


# Example demonstration of policy evaluation for each prompt:
# To test, create a YAML/JSON like:
# policies:
#   - name: allow_admin_full
#     role: admin
#     intent: admin
#     allow_tool: true
#     allow_model: true
#     allow_memory: true
#     max_tokens: 4096
#     terminal: true
#   - name: restrict_high_risk
#     risk_min: 70
#     allow_tool: false
#     allow_model: false
#     allow_memory: false
#     max_tokens: 512
# This example shows a default policy engine loading "vault_policy.yaml".
# Place that file in the same directory.
