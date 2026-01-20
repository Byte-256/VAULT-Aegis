#!/usr/bin/env python3
"""
Simple Test Runner for VAULT Security Framework

This script runs all the simple test files without requiring pytest.
"""

import sys
import os
import subprocess
from pathlib import Path


def run_simple_test(test_file):
    """Run a simple test file and return success status"""
    print(f"\n🧪 Running {test_file.name}...")
    print("=" * 60)

    try:
        result = subprocess.run(
            [sys.executable, str(test_file)],
            capture_output=True,
            text=True,
            cwd=str(test_file.parent.parent.parent),
        )

        if result.returncode == 0:
            print("✅ PASSED")
            print(result.stdout)
            return True
        else:
            print("❌ FAILED")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            return False

    except Exception as e:
        print(f"❌ ERROR running {test_file.name}: {e}")
        return False


def main():
    """Run all simple tests"""
    print("🧪 VAULT Security Framework - Simple Test Runner")
    print("=" * 60)

    project_root = Path(__file__).parent.parent
    tests_dir = project_root / "tests"

    # List of simple test files to run
    simple_tests = [
        tests_dir / "unit" / "test_scanner_simple.py",
        tests_dir / "unit" / "test_policy_simple.py",
        tests_dir / "unit" / "test_audit_simple.py",
        tests_dir / "unit" / "test_gateway_simple.py",
    ]

    total_tests = 0
    passed_tests = 0

    for test_file in simple_tests:
        if test_file.exists():
            total_tests += 1
            if run_simple_test(test_file):
                passed_tests += 1
        else:
            print(f"⚠️  Test file not found: {test_file}")

    print("\n" + "=" * 60)
    print("📊 SIMPLE TEST SUMMARY")
    print("=" * 60)
    print(f"Total tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")

    if passed_tests == total_tests:
        print("\n🎉 ALL SIMPLE TESTS PASSED!")
        print("✅ The VAULT security framework is working correctly!")
        print()
        print("Components tested:")
        print("  🔍 API Scanner")
        print("  ⚖️  Policy Engine")
        print("  📊 Audit Ledger")
        print("  🔗 Gateway Context")
        print()
        return 0
    else:
        print(f"\n⚠️  {total_tests - passed_tests} test(s) failed")
        print("Please check the output above for details.")
        return 1


if __name__ == "__main__":
    exit(main())
