#!/usr/bin/env python3
"""
Simple test runner for VAULT Audit Ledger
"""

import sys
import os
import time
import threading
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def test_audit_ledger():
    """Test VAULT Audit Ledger functionality"""
    print("📊 Testing VAULT Audit Ledger...")

    try:
        from audit.ledger import (
            TamperResistantLedger,
            audit_log_request,
            audit_log_tool,
            forensic_export,
        )

        # Reset singleton to get fresh instance
        TamperResistantLedger._instance = None

        # Test ledger initialization
        print("  ✅ Testing ledger initialization...")
        ledger = TamperResistantLedger()
        assert ledger.chain == []
        assert ledger.last_hash is None
        print("  ✅ Ledger initialization works")

        # Test hash functionality
        print("  ✅ Testing hash functionality...")
        data = {"key1": "value1", "key2": "value2"}
        hash1 = ledger._hash_data(data)

        # Same data should produce same hash
        hash2 = ledger._hash_data(data)
        assert hash1 == hash2

        # Different data should produce different hash
        hash3 = ledger._hash_data({"key1": "different"})
        assert hash1 != hash3

        # Hash should be deterministic based on sorted keys
        hash4 = ledger._hash_data({"key2": "value2", "key1": "value1"})
        assert hash1 == hash4
        print("  ✅ Hash functionality works")

        # Test event logging
        print("  ✅ Testing event logging...")
        ledger.log_event(event_type="test")
        assert len(ledger.chain) == 1

        entry = ledger.chain[0]
        assert entry["type"] == "test"
        assert entry["entry_hash"] is not None
        assert entry["prev_hash"] is None
        print("  ✅ Event logging works")

        # Test event chaining
        print("  ✅ Testing event chaining...")
        first_hash = ledger.chain[0]["entry_hash"]
        ledger.log_event(event_type="second")

        second_entry = ledger.chain[1]
        assert second_entry["prev_hash"] == first_hash
        print("  ✅ Event chaining works")

        # Test audit trail
        print("  ✅ Testing audit trail...")
        trail = ledger.audit_trail()
        assert len(trail) == 2
        assert trail[0]["type"] == "test"
        assert trail[1]["type"] == "second"

        # Should return copies, not references
        trail[0]["type"] = "modified"
        assert ledger.chain[0]["type"] == "test"
        print("  ✅ Audit trail works")

        # Test integrity verification
        print("  ✅ Testing integrity verification...")
        assert ledger.verify_integrity() is True

        # Test tamper detection
        original_hash = ledger.chain[0]["entry_hash"]
        ledger.chain[0]["entry_hash"] = "tampered_hash"
        assert ledger.verify_integrity() is False

        # Restore original hash
        ledger.chain[0]["entry_hash"] = original_hash
        assert ledger.verify_integrity() is True
        print("  ✅ Integrity verification works")

        # Test convenience functions
        print("  ✅ Testing convenience functions...")
        # Reset singleton for clean test
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
        print("  ✅ Convenience functions work")

        # Test thread safety
        print("  ✅ Testing thread safety...")
        # Reset singleton again
        TamperResistantLedger._instance = None
        ledger = TamperResistantLedger()

        results = []

        def log_events(thread_id):
            for i in range(10):
                ledger.log_event(
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
        assert len(ledger.chain) == 50
        assert ledger.verify_integrity() is True
        print("  ✅ Thread safety works")

        # Test data privacy (no raw data storage)
        print("  ✅ Testing data privacy...")
        sensitive_data = {"password": "secret123", "api_key": "sk-12345"}

        ledger.log_event(
            request_data=sensitive_data,
            response_data={"token": "secret_token"},
            event_type="privacy_test",
        )

        entry = ledger.chain[-1]

        # Should only store hashes, not raw data
        assert "secret123" not in str(entry)
        assert "sk-12345" not in str(entry)
        assert "secret_token" not in str(entry)
        assert entry["request_hash"] is not None
        assert entry["response_hash"] is not None
        print("  ✅ Data privacy works")

        print("🎉 All audit ledger tests passed!")
        return True

    except Exception as e:
        print(f"❌ Audit ledger test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run audit ledger tests"""
    print("🧪 VAULT Audit Ledger Tests")
    print("=" * 50)

    success = test_audit_ledger()

    if success:
        print("\n✅ All audit ledger tests completed successfully!")
        return 0
    else:
        print("\n❌ Some audit ledger tests failed!")
        return 1


if __name__ == "__main__":
    exit(main())
