#!/usr/bin/env python3
"""
Simple test runner for VAULT API Scanner
"""

import sys
import os
import json
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def test_scanner():
    """Test VAULT API Scanner functionality"""
    print("🔍 Testing VAULT API Scanner...")

    try:
        from scanner.scanner import VaultAPIScanner, Vulnerability

        # Test vulnerability creation
        print("  ✅ Testing Vulnerability creation...")
        vuln = Vulnerability(
            id="TEST:001",
            title="Test Vulnerability",
            description="Test description",
            endpoint="/test",
            risk="HIGH",
            evidence="Test evidence",
        )

        expected = {
            "id": "TEST:001",
            "title": "Test Vulnerability",
            "description": "Test description",
            "endpoint": "/test",
            "risk": "HIGH",
            "evidence": "Test evidence",
        }

        assert vuln.as_dict() == expected
        print("  ✅ Vulnerability creation works")

        # Test scanner initialization
        print("  ✅ Testing scanner initialization...")
        test_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/public/data": {
                    "get": {
                        "summary": "Get public data",
                        "responses": {"200": {"description": "Success"}},
                    }
                }
            },
        }

        scanner = VaultAPIScanner(test_spec)
        assert scanner.spec == test_spec
        assert scanner.vulns == []
        print("  ✅ Scanner initialization works")

        # Test vulnerability detection
        print("  ✅ Testing vulnerability detection...")
        vulnerable_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Insecure API", "version": "1.0.0"},
            "servers": [{"url": "http://api.example.com"}],  # HTTP instead of HTTPS
            "paths": {
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "security": [],  # No security required
                        "responses": {"200": {"description": "Success"}},
                    }
                }
            },
        }

        scanner = VaultAPIScanner(vulnerable_spec)
        scanner.scan()

        assert len(scanner.vulns) > 0
        print(f"  ✅ Found {len(scanner.vulns)} vulnerabilities")

        # Test report generation
        print("  ✅ Testing report generation...")
        report = scanner.generate_report()
        assert "summary" in report
        assert "vulnerabilities" in report
        assert report["summary"]["total_vulnerabilities"] == len(scanner.vulns)
        print("  ✅ Report generation works")

        print("🎉 All scanner tests passed!")
        return True

    except Exception as e:
        print(f"❌ Scanner test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run scanner tests"""
    print("🧪 VAULT API Scanner Tests")
    print("=" * 50)

    success = test_scanner()

    if success:
        print("\n✅ All scanner tests completed successfully!")
        return 0
    else:
        print("\n❌ Some scanner tests failed!")
        return 1


if __name__ == "__main__":
    exit(main())
