#!/usr/bin/env python3
"""
Run All Demos Script

This script runs all demo scripts for the VAULT security framework.
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


def run_demo(demo_path):
    """Run a single demo script"""
    print(f"\n🚀 Running {demo_path.name}...")
    print("=" * 80)

    try:
        # Import and run the demo
        if demo_path.name == "vault_demo.py":
            from tests.demo.vault_demo import main as demo_main

            return demo_main()
        else:
            # For future demo scripts
            print(f"Demo {demo_path.name} not implemented yet")
            return 0

    except Exception as e:
        print(f"❌ Demo {demo_path.name} failed with error: {e}")
        import traceback

        traceback.print_exc()
        return 1


def main():
    """Run all demo scripts"""
    print("🏛️  VAULT Security Framework - Demo Runner")
    print("This script runs all available demos for the VAULT security framework")
    print()

    demo_dir = Path(__file__).parent
    demo_scripts = [
        demo_dir / "vault_demo.py",
        # Add more demo scripts here as they are created
        # demo_dir / "scanner_demo.py",
        # demo_dir / "policy_demo.py",
        # demo_dir / "gateway_demo.py",
    ]

    total_demos = 0
    successful_demos = 0

    for demo_script in demo_scripts:
        if demo_script.exists():
            total_demos += 1
            exit_code = run_demo(demo_script)
            if exit_code == 0:
                successful_demos += 1
            else:
                print(f"❌ Demo failed with exit code {exit_code}")
        else:
            print(f"⚠️  Demo script not found: {demo_script}")

    print("\n" + "=" * 80)
    print("📊 DEMO SUMMARY")
    print("=" * 80)
    print(f"Total demos: {total_demos}")
    print(f"Successful: {successful_demos}")
    print(f"Failed: {total_demos - successful_demos}")

    if successful_demos == total_demos:
        print("\n🎉 All demos completed successfully!")
        print("✅ The VAULT security framework is working correctly!")
        return 0
    else:
        print(f"\n⚠️  {total_demos - successful_demos} demo(s) failed")
        return 1


if __name__ == "__main__":
    exit(main())
