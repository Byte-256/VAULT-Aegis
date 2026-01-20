import pytest
import time
from unittest.mock import patch
from audit.ledger import (
    TamperResistantLedger,
    audit_log_request,
    audit_log_tool,
    forensic_export,
)


class TestTamperResistantLedger:
    """Test suite for VAULT Audit Ledger"""

    @pytest.fixture
    def fresh_ledger(self):
        """Create a fresh ledger instance for each test"""
        # Reset singleton to get fresh instance
        TamperResistantLedger._instance = None
        return TamperResistantLedger()

    @pytest.fixture
    def populated_ledger(self, fresh_ledger):
        """Create a ledger with some sample entries"""
        fresh_ledger.log_event(
            request_data={"prompt": "Hello world", "user": "user123"},
            intent="chat",
            risk=10,
            policy_decision="allow",
            event_type="request",
        )
        fresh_ledger.log_event(
            tool_name="llm_generation",
            request_data={"prompt": "Hello world"},
            response_data={"content": "Hello! How can I help you?"},
            policy_decision="allow",
            event_type="tool",
        )
        return fresh_ledger

    def test_singleton_pattern(self):
        """Test that ledger follows singleton pattern"""
        # Reset singleton
        TamperResistantLedger._instance = None

        ledger1 = TamperResistantLedger()
        ledger2 = TamperResistantLedger()

        assert ledger1 is ledger2
        assert id(ledger1) == id(ledger2)

    def test_ledger_initialization(self, fresh_ledger):
        """Test ledger initialization"""
        assert fresh_ledger.chain == []
        assert fresh_ledger.last_hash is None

    def test_hash_data(self, fresh_ledger):
        """Test data hashing functionality"""
        data = {"key1": "value1", "key2": "value2"}
        hash1 = fresh_ledger._hash_data(data)

        # Same data should produce same hash
        hash2 = fresh_ledger._hash_data(data)
        assert hash1 == hash2

        # Different data should produce different hash
        hash3 = fresh_ledger._hash_data({"key1": "different"})
        assert hash1 != hash3

        # Hash should be deterministic based on sorted keys
        hash4 = fresh_ledger._hash_data({"key2": "value2", "key1": "value1"})
        assert hash1 == hash4

    def test_ledger_entry_creation(self, fresh_ledger):
        """Test ledger entry creation"""
        entry_data = {
            "type": "test",
            "request_hash": "abc123",
            "intent": "chat",
            "risk": 10,
        }

        with patch("time.time", return_value=1234567890):
            entry = fresh_ledger._ledger_entry(entry_data)

        assert entry["type"] == "test"
        assert entry["request_hash"] == "abc123"
        assert entry["intent"] == "chat"
        assert entry["risk"] == 10
        assert entry["timestamp"] == 1234567890
        assert entry["prev_hash"] is None
        assert "entry_hash" in entry

    def test_log_event_minimal(self, fresh_ledger):
        """Test logging minimal event"""
        fresh_ledger.log_event()

        assert len(fresh_ledger.chain) == 1
        entry = fresh_ledger.chain[0]
        assert entry["type"] == "event"
        assert entry["request_hash"] is None
        assert entry["response_hash"] is None

    def test_log_event_full(self, fresh_ledger):
        """Test logging full event with all parameters"""
        with patch("time.time", return_value=1234567890):
            fresh_ledger.log_event(
                request_data={"prompt": "test", "user": "user123"},
                intent="chat",
                risk=25,
                policy_decision="allow",
                tool="llm_generation",
                response_data={"content": "response"},
                details={"session_id": "sess123"},
                event_type="test_event",
            )

        assert len(fresh_ledger.chain) == 1
        entry = fresh_ledger.chain[0]

        assert entry["type"] == "test_event"
        assert entry["intent"] == "chat"
        assert entry["risk"] == 25
        assert entry["policy_decision"] == "allow"
        assert entry["tool"] == "llm_generation"
        assert entry["details"] == {"session_id": "sess123"}
        assert entry["timestamp"] == 1234567890
        assert entry["request_hash"] is not None
        assert entry["response_hash"] is not None

    def test_log_event_chaining(self, fresh_ledger):
        """Test that events are properly chained"""
        # Log first event
        fresh_ledger.log_event(event_type="first")
        first_entry = fresh_ledger.chain[0]
        first_hash = first_entry["entry_hash"]
        assert first_entry["prev_hash"] is None

        # Log second event
        fresh_ledger.log_event(event_type="second")
        second_entry = fresh_ledger.chain[1]
        assert second_entry["prev_hash"] == first_hash

        # Log third event
        fresh_ledger.log_event(event_type="third")
        third_entry = fresh_ledger.chain[2]
        assert third_entry["prev_hash"] == second_entry["entry_hash"]

    def test_audit_trail(self, populated_ledger):
        """Test audit trail retrieval"""
        trail = populated_ledger.audit_trail()

        assert len(trail) == 2
        assert trail[0]["type"] == "request"
        assert trail[1]["type"] == "tool"

        # Should return copies, not references
        trail[0]["type"] = "modified"
        assert populated_ledger.chain[0]["type"] == "request"

    def test_verify_integrity_empty(self, fresh_ledger):
        """Test integrity verification on empty ledger"""
        assert fresh_ledger.verify_integrity() is True

    def test_verify_integrity_valid(self, populated_ledger):
        """Test integrity verification on valid ledger"""
        assert populated_ledger.verify_integrity() is True

    def test_verify_integrity_tampered_hash(self, populated_ledger):
        """Test integrity detection when entry hash is tampered"""
        # Tamper with an entry hash
        populated_ledger.chain[0]["entry_hash"] = "tampered_hash"

        assert populated_ledger.verify_integrity() is False

    def test_verify_integrity_tampered_chain(self, populated_ledger):
        """Test integrity detection when chain linkage is broken"""
        # Tamper with chain linkage
        populated_ledger.chain[1]["prev_hash"] = "wrong_hash"

        assert populated_ledger.verify_integrity() is False

    def test_verify_integrity_tampered_data(self, populated_ledger):
        """Test integrity detection when entry data is tampered"""
        # Tamper with entry data
        original_hash = populated_ledger.chain[0]["entry_hash"]
        populated_ledger.chain[0]["risk"] = 999

        assert populated_ledger.verify_integrity() is False

        # Restore original hash to verify it fails
        populated_ledger.chain[0]["entry_hash"] = original_hash
        assert populated_ledger.verify_integrity() is False

    def test_thread_safety(self, fresh_ledger):
        """Test thread safety of ledger operations"""
        import threading

        results = []

        def log_events(thread_id):
            for i in range(10):
                fresh_ledger.log_event(
                    request_data={"thread": thread_id, "index": i},
                    event_type=f"thread_{thread_id}",
                )

        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=log_events, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Should have all events logged
        assert len(fresh_ledger.chain) == 50
        assert fresh_ledger.verify_integrity() is True

    def test_audit_log_request_function(self):
        """Test audit_log_request convenience function"""
        # Reset singleton
        TamperResistantLedger._instance = None

        audit_log_request(
            request_obj={"prompt": "test", "user": "user123"},
            intent="chat",
            risk=15,
            policy_decision="allow",
        )

        ledger = TamperResistantLedger()
        assert len(ledger.chain) == 1
        entry = ledger.chain[0]
        assert entry["type"] == "request"
        assert entry["intent"] == "chat"
        assert entry["risk"] == 15
        assert entry["policy_decision"] == "allow"

    def test_audit_log_tool_function(self):
        """Test audit_log_tool convenience function"""
        # Reset singleton
        TamperResistantLedger._instance = None

        audit_log_tool(
            tool_name="file_reader",
            request_obj={"file": "data.txt"},
            response_obj={"content": "file content"},
            policy_decision="allow",
            details={"execution_time": 0.5},
        )

        ledger = TamperResistantLedger()
        assert len(ledger.chain) == 1
        entry = ledger.chain[0]
        assert entry["type"] == "tool"
        assert entry["tool"] == "file_reader"
        assert entry["details"]["execution_time"] == 0.5

    def test_forensic_export_function(self):
        """Test forensic_export function"""
        # Reset singleton and populate with data
        TamperResistantLedger._instance = None

        audit_log_request(
            request_obj={"prompt": "test"},
            intent="chat",
            risk=10,
            policy_decision="allow",
        )

        trail = forensic_export()
        assert len(trail) == 1
        assert trail[0]["type"] == "request"

    def test_forensic_export_integrity_failure(self):
        """Test forensic_export with integrity failure"""
        # Reset singleton
        TamperResistantLedger._instance = None

        # Add entry and tamper with it
        ledger = TamperResistantLedger()
        ledger.log_event(event_type="test")
        ledger.chain[0]["entry_hash"] = "tampered"

        with pytest.raises(AssertionError, match="Ledger integrity check failed"):
            forensic_export()

    def test_request_response_data_not_stored_raw(self, fresh_ledger):
        """Test that raw request/response data is not stored"""
        sensitive_data = {"password": "secret123", "api_key": "sk-12345"}

        fresh_ledger.log_event(
            request_data=sensitive_data,
            response_data={"token": "secret_token"},
            event_type="test",
        )

        entry = fresh_ledger.chain[0]

        # Should only store hashes, not raw data
        assert sensitive_data not in str(entry)
        assert "secret123" not in str(entry)
        assert "sk-12345" not in str(entry)
        assert "secret_token" not in str(entry)
        assert entry["request_hash"] is not None
        assert entry["response_hash"] is not None

    def test_hash_consistency_across_entries(self, fresh_ledger):
        """Test that same data produces same hash across different entries"""
        data = {"test": "data"}

        fresh_ledger.log_event(request_data=data, event_type="first")
        fresh_ledger.log_event(request_data=data, event_type="second")

        entry1 = fresh_ledger.chain[0]
        entry2 = fresh_ledger.chain[1]

        # Same request data should produce same hash
        assert entry1["request_hash"] == entry2["request_hash"]

    def test_ledger_last_hash_tracking(self, fresh_ledger):
        """Test that last_hash is properly tracked"""
        assert fresh_ledger.last_hash is None

        fresh_ledger.log_event(event_type="first")
        first_hash = fresh_ledger.last_hash
        assert first_hash is not None

        fresh_ledger.log_event(event_type="second")
        second_hash = fresh_ledger.last_hash
        assert second_hash != first_hash
        assert second_hash == fresh_ledger.chain[-1]["entry_hash"]
