import argparse
import json
import os
import sys

def run_cicd_scan():
    parser = argparse.ArgumentParser(
        description="VAULT API Security Scanner - CI/CD Mode"
    )
    parser.add_argument(
        "openapi_file",
        type=str,
        help="Path to OpenAPI spec (JSON or YAML)"
    )
    parser.add_argument(
        "--output-json",
        type=str,
        required=False,
        help="Write machine-readable report to this file"
    )
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Fail (exit 1) if high-severity vulnerabilities are found"
    )
    args = parser.parse_args()

    from scanner.scanner import VaultAPIScanner
    report = VaultAPIScanner.quick_scan_file(args.openapi_file)
    high_findings = [
        v for v in report.get("vulnerabilities", [])
        if v.get("risk", "").upper() == "HIGH"
    ]

    # Output human summary
    print(json.dumps(report, indent=2))

    # Write machine-readable report if requested
    if args.output_json:
        try:
            with open(args.output_json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"Wrote JSON report to {args.output_json}")
        except Exception as ex:
            print(f"Failed to write output JSON: {ex}")
            exit(2)

    # Fail build on high risk, if requested
    if args.fail_on_high and high_findings:
        print(
            f"\n::error ::{len(high_findings)} high-severity vulnerabilities detected. Failing build."
        )
        exit(1)

# Example CLI entrypoint
if __name__ == "__main__":
    from scanner.scanner import VaultAPIScanner
    if len(sys.argv) < 2:
        print("Usage: python cli.py openapi.json")
        print("       python cli.py openapi.json --output-json report.json --fail-on-high")
    else:
        # Check for CI/CD mode
        if os.environ.get("VAULT_CI", "").lower() == "1" or "--cicd" in sys.argv:
            if "--cicd" in sys.argv:
                sys.argv.remove("--cicd")
            run_cicd_scan()
        else:
            # Simple scan mode
            report = VaultAPIScanner.quick_scan_file(sys.argv[1])
            print(json.dumps(report, indent=2))
