#!/usr/bin/env python3
"""
Simple test runner for VAULT Policy Engine
"""

import sys
import os
import tempfile
import yaml
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def test_policy_engine():
    """Test VAULT Policy Engine functionality"""
    print("⚖️ Testing VAULT Policy Engine...")

    try:
        from policy.engine import VaultPolicyEngine, PolicyDecision
        from gateway.context import IntentMetadata, IntentType

        # Test policy decision creation
        print("  ✅ Testing PolicyDecision creation...")
        decision = PolicyDecision(
            allow_tool=True,
            allow_model=False,
            allow_memory=False,
            max_tokens=2048,
            reasons=["Test reason"],
            matched_policy="test_policy",
        )

        expected = {
            "allow_tool": True,
            "allow_model": False,
            "allow_memory": False,
            "max_tokens": 2048,
            "reasons": ["Test reason"],
            "matched_policy": "test_policy",
        }

        assert decision.as_dict() == expected
        print("  ✅ PolicyDecision creation works")

        # Test policy engine with temporary file
        print("  ✅ Testing policy engine with file...")
        test_policies = {
            "policies": [
                {
                    "name": "allow_admin_full",
                    "role": "admin",
                    "intent": "admin",
                    "allow_tool": True,
                    "allow_model": True,
                    "allow_memory": True,
                    "max_tokens": 4096,
                    "terminal": True,
                },
                {
                    "name": "restrict_high_risk",
                    "risk_min": 70,
                    "allow_tool": False,
                    "allow_model": False,
                    "allow_memory": False,
                    "max_tokens": 512,
                    "terminal": True,
                },
                {
                    "name": "allow_user_chat",
                    "role": "user",
                    "intent": "chat",
                    "allow_model": True,
                    "max_tokens": 2048,
                },
            ]
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(test_policies, f)
            temp_file = f.name

        try:
            engine = VaultPolicyEngine(temp_file)
            assert engine.policy_path == temp_file
            assert "policies" in engine.policies
            assert len(engine.policies["policies"]) == 3
            print("  ✅ Policy engine initialization works")

            # Test admin policy evaluation
            print("  ✅ Testing admin policy evaluation...")
            admin_intent = IntentMetadata(
                intent=IntentType.ADMIN,
                risk_score=10,
                reason="admin test",
                confidence=0.95,
            )

            decision = engine.evaluate(
                intent_metadata=admin_intent, user_role="admin", scope="external"
            )

            assert decision.allow_tool is True
            assert decision.allow_model is True
            assert decision.allow_memory is True
            assert decision.max_tokens == 4096
            assert decision.matched_policy == "allow_admin_full"
            print("  ✅ Admin policy evaluation works")

            # Test high risk restriction
            print("  ✅ Testing high risk restriction...")
            high_risk_intent = IntentMetadata(
                intent=IntentType.CHAT,
                risk_score=80,
                reason="high risk test",
                confidence=0.8,
            )

            decision = engine.evaluate(
                intent_metadata=high_risk_intent, user_role="user", scope="external"
            )

            assert decision.allow_tool is False
            assert decision.allow_model is False
            assert decision.allow_memory is False
            assert decision.max_tokens == 512
            assert decision.matched_policy == "restrict_high_risk"
            print("  ✅ High risk restriction works")

            # Test user chat policy
            print("  ✅ Testing user chat policy...")
            chat_intent = IntentMetadata(
                intent=IntentType.CHAT,
                risk_score=30,
                reason="chat test",
                confidence=0.9,
            )

            decision = engine.evaluate(
                intent_metadata=chat_intent, user_role="user", scope="external"
            )

            assert decision.allow_model is True
            assert decision.max_tokens == 2048
            assert decision.matched_policy == "allow_user_chat"
            print("  ✅ User chat policy works")

            # Test default fallback
            print("  ✅ Testing default policy fallback...")
            unknown_intent = IntentMetadata(
                intent=IntentType.UNKNOWN,
                risk_score=50,
                reason="unknown test",
                confidence=0.5,
            )

            decision = engine.evaluate(
                intent_metadata=unknown_intent, user_role="guest", scope="internal"
            )

            assert decision.allow_model is True  # Default value
            assert decision.max_tokens == 1024  # Default value
            assert decision.matched_policy == "default"
            print("  ✅ Default policy fallback works")

        finally:
            os.unlink(temp_file)

        print("🎉 All policy engine tests passed!")
        return True

    except Exception as e:
        print(f"❌ Policy engine test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run policy engine tests"""
    print("🧪 VAULT Policy Engine Tests")
    print("=" * 50)

    success = test_policy_engine()

    if success:
        print("\n✅ All policy engine tests completed successfully!")
        return 0
    else:
        print("\n❌ Some policy engine tests failed!")
        return 1


if __name__ == "__main__":
    exit(main())
