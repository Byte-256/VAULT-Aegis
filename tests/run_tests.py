#!/usr/bin/env python3
"""
Test Runner for VAULT Security Framework

This script provides a convenient way to run all tests for the VAULT framework.
"""

import sys
import os
import subprocess
from pathlib import Path


def run_command(cmd, cwd=None):
    """Run a command and return the result"""
    try:
        result = subprocess.run(
            cmd, shell=True, cwd=cwd, capture_output=True, text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def run_tests():
    """Run all tests for the VAULT framework"""
    print("🧪 VAULT Security Framework - Test Runner")
    print("=" * 60)

    project_root = Path(__file__).parent.parent
    tests_dir = project_root / "tests"

    if not tests_dir.exists():
        print(f"❌ Tests directory not found: {tests_dir}")
        return 1

    print(f"📁 Running tests from: {tests_dir}")
    print()

    # Check if pytest is available
    success, _, _ = run_command("python -m pytest --version")
    if not success:
        print("❌ pytest not found. Installing...")
        success, _, error = run_command("python -m pip install pytest")
        if not success:
            print(f"❌ Failed to install pytest: {error}")
            return 1
        print("✅ pytest installed successfully")

    # Run unit tests
    print("🔬 Running Unit Tests...")
    print("-" * 40)
    success, stdout, stderr = run_command(f"python -m pytest {tests_dir}/unit/ -v")

    if success:
        print("✅ Unit tests passed!")
        print(stdout)
    else:
        print("❌ Unit tests failed!")
        print(stderr)

    # Run integration tests
    print("\n🔗 Running Integration Tests...")
    print("-" * 40)
    success2, stdout2, stderr2 = run_command(
        f"python -m pytest {tests_dir}/integration/ -v"
    )

    if success2:
        print("✅ Integration tests passed!")
        print(stdout2)
    else:
        print("❌ Integration tests failed!")
        print(stderr2)

    # Run all tests together
    print("\n🎯 Running All Tests...")
    print("-" * 40)
    success3, stdout3, stderr3 = run_command(
        f"python -m pytest {tests_dir}/ -v --tb=short"
    )

    if success3:
        print("✅ All tests passed!")
        print(stdout3)
    else:
        print("❌ Some tests failed!")
        print(stderr3)

    # Run demos
    print("\n🎬 Running Framework Demos...")
    print("-" * 40)
    demo_script = tests_dir / "demo" / "run_all_demos.py"
    if demo_script.exists():
        success4, stdout4, stderr4 = run_command(f"python {demo_script}")

        if success4:
            print("✅ All demos completed successfully!")
            print(stdout4)
        else:
            print("❌ Some demos failed!")
            print(stderr4)
    else:
        print("⚠️  Demo script not found")
        success4 = True

    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)

    all_passed = success and success2 and success3 and success4

    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("✅ The VAULT security framework is working correctly!")
        print()
        print("Components tested:")
        print("  🔍 API Scanner")
        print("  ⚖️  Policy Engine")
        print("  🔐 Authentication Middleware")
        print("  📊 Audit Ledger")
        print("  🔗 API Integration")
        print("  🎬 Framework Demos")
        print()
        return 0
    else:
        print("❌ SOME TESTS FAILED!")
        print()
        print("Please check the output above for details.")
        return 1


def main():
    """Main entry point"""
    try:
        return run_tests()
    except KeyboardInterrupt:
        print("\n⚠️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Test runner failed with error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
