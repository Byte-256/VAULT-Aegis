import pytest
import tempfile
import os
from unittest.mock import Mock
from policy.engine import VaultPolicyEngine, PolicyDecision
from gateway.context import IntentMetadata, IntentType


class TestPolicyEngine:
    """Test suite for VAULT Policy Engine"""

    @pytest.fixture
    def sample_policy_config(self):
        """Sample policy configuration for testing"""
        return {
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
                },
                {
                    "name": "allow_user_chat",
                    "role": "user",
                    "intent": "chat",
                    "allow_model": True,
                    "max_tokens": 2048,
                },
                {"name": "default_policy", "allow_model": True, "max_tokens": 1024},
            ]
        }

    @pytest.fixture
    def temp_policy_file(self, sample_policy_config):
        """Create temporary policy file"""
        import yaml

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(sample_policy_config, f)
            temp_file = f.name

        yield temp_file

        # Cleanup
        os.unlink(temp_file)

    @pytest.fixture
    def policy_engine(self, temp_policy_file):
        """Create policy engine instance"""
        return VaultPolicyEngine(temp_policy_file)

    @pytest.fixture
    def sample_intent_metadata(self):
        """Sample intent metadata for testing"""
        return IntentMetadata(
            intent=IntentType.CHAT, risk_score=30, reason="test", confidence=0.9
        )

    def test_policy_decision_creation(self):
        """Test PolicyDecision object creation"""
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

    def test_policy_engine_initialization(self, temp_policy_file):
        """Test policy engine initialization"""
        engine = VaultPolicyEngine(temp_policy_file)
        assert engine.policy_path == temp_policy_file
        assert "policies" in engine.policies
        assert len(engine.policies["policies"]) > 0

    def test_load_policies_yaml(self, sample_policy_config):
        """Test loading policies from YAML file"""
        import yaml

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(sample_policy_config, f)
            temp_file = f.name

        try:
            engine = VaultPolicyEngine(temp_file)
            assert engine.policies == sample_policy_config
        finally:
            os.unlink(temp_file)

    def test_load_policies_json(self, sample_policy_config):
        """Test loading policies from JSON file"""
        import json

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(sample_policy_config, f)
            temp_file = f.name

        try:
            engine = VaultPolicyEngine(temp_file)
            assert engine.policies == sample_policy_config
        finally:
            os.unlink(temp_file)

    def test_load_policies_unsupported_format(self):
        """Test error handling for unsupported file format"""
        with pytest.raises(ValueError, match="Policy format not supported"):
            VaultPolicyEngine("test.txt")

    def test_evaluate_admin_full_access(self, policy_engine):
        """Test policy evaluation for admin with full access"""
        admin_intent = IntentMetadata(
            intent=IntentType.ADMIN, risk_score=10, reason="admin test", confidence=0.95
        )

        decision = policy_engine.evaluate(
            intent_metadata=admin_intent, user_role="admin", scope="external"
        )

        assert decision.allow_tool is True
        assert decision.allow_model is True
        assert decision.allow_memory is True
        assert decision.max_tokens == 4096
        assert decision.matched_policy == "allow_admin_full"

    def test_evaluate_high_risk_restriction(self, policy_engine):
        """Test policy evaluation for high risk requests"""
        high_risk_intent = IntentMetadata(
            intent=IntentType.CHAT,
            risk_score=80,
            reason="high risk test",
            confidence=0.8,
        )

        decision = policy_engine.evaluate(
            intent_metadata=high_risk_intent, user_role="user", scope="external"
        )

        assert decision.allow_tool is False
        assert decision.allow_model is False
        assert decision.allow_memory is False
        assert decision.max_tokens == 512
        assert decision.matched_policy == "restrict_high_risk"

    def test_evaluate_user_chat(self, policy_engine, sample_intent_metadata):
        """Test policy evaluation for regular user chat"""
        decision = policy_engine.evaluate(
            intent_metadata=sample_intent_metadata, user_role="user", scope="external"
        )

        assert decision.allow_model is True
        assert decision.max_tokens == 2048
        assert decision.matched_policy == "allow_user_chat"

    def test_evaluate_no_match_fallback(self, policy_engine):
        """Test policy evaluation when no specific policy matches"""
        unusual_intent = IntentMetadata(
            intent=IntentType.UNKNOWN,
            risk_score=50,
            reason="unknown test",
            confidence=0.5,
        )

        decision = policy_engine.evaluate(
            intent_metadata=unusual_intent, user_role="guest", scope="internal"
        )

        assert decision.allow_model is True  # Default value
        assert decision.max_tokens == 1024  # Default value
        assert decision.matched_policy == "default"

    def test_policy_matching_conditions(self):
        """Test various policy matching conditions"""
        policies_config = {
            "policies": [
                {
                    "name": "role_specific",
                    "role": "manager",
                    "allow_model": True,
                    "max_tokens": 3000,
                },
                {
                    "name": "scope_specific",
                    "scope": "internal",
                    "allow_model": True,
                    "max_tokens": 5000,
                },
                {
                    "name": "risk_range",
                    "risk_min": 20,
                    "risk_max": 60,
                    "allow_model": True,
                    "max_tokens": 1500,
                },
            ]
        }

        import yaml

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policies_config, f)
            temp_file = f.name

        try:
            engine = VaultPolicyEngine(temp_file)

            # Test role matching
            intent = IntentMetadata(IntentType.CHAT, 30, "role test")
            decision = engine.evaluate(intent, user_role="manager")
            assert decision.matched_policy == "role_specific"

            # Test scope matching
            decision = engine.evaluate(intent, user_role="user", scope="internal")
            assert decision.matched_policy == "scope_specific"

            # Test risk range matching
            decision = engine.evaluate(intent, user_role="user", scope="external")
            assert decision.matched_policy == "risk_range"

        finally:
            os.unlink(temp_file)

    def test_terminal_policy_stops_evaluation(self):
        """Test that terminal policies stop further evaluation"""
        policies_config = {
            "policies": [
                {
                    "name": "first_policy",
                    "role": "admin",
                    "allow_model": True,
                    "max_tokens": 2000,
                    "terminal": True,
                },
                {
                    "name": "second_policy",
                    "role": "admin",
                    "allow_model": False,
                    "max_tokens": 500,
                },
            ]
        }

        import yaml

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policies_config, f)
            temp_file = f.name

        try:
            engine = VaultPolicyEngine(temp_file)
            intent = IntentMetadata(IntentType.CHAT, 10, "terminal test")

            decision = engine.evaluate(intent, user_role="admin")

            # Should match first policy and stop (terminal=True)
            assert decision.matched_policy == "first_policy"
            assert decision.allow_model is True
            assert decision.max_tokens == 2000

        finally:
            os.unlink(temp_file)

    def test_max_tokens_cumulative_effect(self):
        """Test that max_tokens is properly limited across policies"""
        policies_config = {
            "policies": [
                {"name": "policy_1", "max_tokens": 4000},
                {"name": "policy_2", "max_tokens": 2000},
                {"name": "policy_3", "max_tokens": 3000},
            ]
        }

        import yaml

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policies_config, f)
            temp_file = f.name

        try:
            engine = VaultPolicyEngine(temp_file)
            intent = IntentMetadata(IntentType.CHAT, 20, "cumulative test")

            decision = engine.evaluate(intent)

            # Should use the minimum (2000) due to cumulative effect
            assert decision.max_tokens == 2000

        finally:
            os.unlink(temp_file)

    def test_evaluate_with_missing_optional_fields(self):
        """Test policy evaluation with minimal policy configuration"""
        minimal_config = {
            "policies": [
                {
                    "name": "minimal_policy"
                    # No optional fields specified
                }
            ]
        }

        import yaml

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(minimal_config, f)
            temp_file = f.name

        try:
            engine = VaultPolicyEngine(temp_file)
            intent = IntentMetadata(IntentType.CHAT, 30, "minimal test")

            decision = engine.evaluate(intent)

            # Should use default values
            assert decision.allow_tool is False  # Default
            assert decision.allow_model is True  # Default
            assert decision.allow_memory is False  # Default
            assert decision.max_tokens == 1024  # Default

        finally:
            os.unlink(temp_file)
