import json
import re
from typing import List, Dict, Any, Optional

class Vulnerability:
    def __init__(self, id: str, title: str, description: str, endpoint: str, risk: str, evidence: Optional[str] = None):
        self.id = id
        self.title = title
        self.description = description
        self.endpoint = endpoint
        self.risk = risk
        self.evidence = evidence

    def as_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "endpoint": self.endpoint,
            "risk": self.risk,
            "evidence": self.evidence
        }

class VaultAPIScanner:
    """
    Automated API Security Scanner for VAULT
    Consumes OpenAPI/Swagger specs and detects OWASP API Top 10 risks.
    Also runs basic live tests for authentication, authorization, and rate limits via supplied runner hooks.
    """

    # OWASP API Top 10 2023 Risk mapping
    OWASP_TOP10 = [
        {"id": "API1:2023", "name": "Broken Object Level Authorization"},
        {"id": "API2:2023", "name": "Broken Authentication"},
        {"id": "API3:2023", "name": "Broken Object Property Level Authorization"},
        {"id": "API4:2023", "name": "Unrestricted Resource Consumption"},
        {"id": "API5:2023", "name": "Broken Function Level Authorization"},
        {"id": "API6:2023", "name": "Unrestricted Access to Sensitive Business Flows"},
        {"id": "API7:2023", "name": "Server Side Request Forgery"},
        {"id": "API8:2023", "name": "Security Misconfiguration"},
        {"id": "API9:2023", "name": "Improper Inventory Management"},
        {"id": "API10:2023", "name": "Unsafe Consumption of APIs"},
    ]
    def __init__(self, openapi_dict: Dict[str, Any]):
        self.spec = openapi_dict
        self.vulns: List[Vulnerability] = []

    def scan(self):
        self.check_auth()
        self.check_authorization()
        self.check_rate_limits()
        self.check_misconfigurations()
        self.check_unsafe_endpoints()
        self.check_owasp_top_10_patterns()

    def check_auth(self):
        # Broken Authentication (API2)
        security = self.spec.get("security", []) or self.spec.get("components", {}).get("securitySchemes", {})
        if not security:
            self.vulns.append(Vulnerability(
                id="API2:2023",
                title="Broken Authentication",
                description="No global or component security schemes defined. API may lack authentication enforcement.",
                endpoint="ALL",
                risk="HIGH"
            ))
        paths = self.spec.get("paths", {})
        for path, defs in paths.items():
            for method, obj in defs.items():
                if not obj or not isinstance(obj, dict):
                    continue
                sec = obj.get("security")
                if sec is None and not security:
                    self.vulns.append(Vulnerability(
                        id="API2:2023",
                        title="Broken Authentication",
                        description="Endpoint has no authentication requirement (no security property)",
                        endpoint=f"{method.upper()} {path}",
                        risk="HIGH"
                    ))

    def check_authorization(self):
        # Broken Object Level / Function Level Authorization (API1, API3, API5)
        paths = self.spec.get("paths", {})
        for path, defs in paths.items():
            # Look for common object id in path
            if re.search(r"\{.*id.*\}", path, re.IGNORECASE):
                for method, obj in defs.items():
                    parameters = obj.get("parameters", []) if isinstance(obj, dict) else []
                    # Warn if parameters are not secured
                    if not obj.get("security"):
                        self.vulns.append(Vulnerability(
                            id="API1:2023",
                            title="Broken Object Level Authorization",
                            description="Object-level endpoint does not declare security (may allow IDOR)",
                            endpoint=f"{method.upper()} {path}",
                            risk="HIGH"
                        ))
            # Check for anything with 'admin' or 'priv' in route without auth
            if re.search(r"/(admin|priv|internal)", path):
                for method, obj in defs.items():
                    if not obj.get("security"):
                        self.vulns.append(Vulnerability(
                            id="API5:2023",
                            title="Broken Function Level Authorization",
                            description="Privileged endpoint lacks declared security",
                            endpoint=f"{method.upper()} {path}",
                            risk="HIGH"
                        ))

    def check_rate_limits(self):
        # Unrestricted Resource Consumption (API4)
        global_x_rate = self.spec.get("x-rate-limit") or self.spec.get("x-throttling")
        if not global_x_rate:
            # Check per-path rate limit
            paths = self.spec.get("paths", {})
            for path, defs in paths.items():
                for method, obj in defs.items():
                    if not isinstance(obj, dict):
                        continue
                    rl = obj.get("x-rate-limit") or obj.get("x-throttling")
                    if not rl:
                        self.vulns.append(Vulnerability(
                            id="API4:2023",
                            title="Unrestricted Resource Consumption",
                            description="Missing rate limiting on endpoint.",
                            endpoint=f"{method.upper()} {path}",
                            risk="MEDIUM"
                        ))

    def check_misconfigurations(self):
        # Security Misconfiguration/API8
        servers = self.spec.get("servers", [])
        insecure_found = False
        for srv in servers:
            url = srv.get("url") if isinstance(srv, dict) else str(srv)
            if url and url.startswith("http://"):
                self.vulns.append(Vulnerability(
                    id="API8:2023",
                    title="Insecure Transport Protocol",
                    description="OpenAPI server uses HTTP (should be HTTPS).",
                    endpoint=url,
                    risk="HIGH"
                ))
                insecure_found = True
        # CORS headers (basic pattern)
        if self.spec.get("components", {}).get("securitySchemes"):
            cors = self.spec.get("x-cors") or self.spec.get("x-cors-allow-origin")
            if cors == "*" or (isinstance(cors, str) and "*" in cors):
                self.vulns.append(Vulnerability(
                    id="API8:2023",
                    title="Overly Permissive CORS Policy",
                    description="CORS policy allows any origin.",
                    endpoint="ALL",
                    risk="MEDIUM"
                ))
        # Check for default or empty API keys, tokens
        comps = self.spec.get("components", {}).get("securitySchemes", {})
        for key, scheme in comps.items():
            if "apiKey" in scheme.get("type", "").lower() and not scheme.get("name"):
                self.vulns.append(Vulnerability(
                    id="API2:2023",
                    title="Missing API Key",
                    description=f"API Key security scheme '{key}' lacks 'name'.",
                    endpoint="ALL",
                    risk="HIGH"
                ))

    def check_unsafe_endpoints(self):
        # Unsafe functions (API10)
        for path, defs in self.spec.get("paths", {}).items():
            for method, obj in defs.items():
                # Dangerous HTTP methods
                if method.lower() in {"put", "delete", "patch"}:
                    if not obj.get("security"):
                        self.vulns.append(Vulnerability(
                            id="API10:2023",
                            title="Unsafe Method on Unprotected Endpoint",
                            description="Dangerous HTTP method exposed without protection.",
                            endpoint=f"{method.upper()} {path}",
                            risk="HIGH"
                        ))
                # Check for file upload/download endpoints
                if 'requestBody' in obj and 'content' in obj['requestBody']:
                    if any('octet-stream' in ctype or 'multipart' in ctype for ctype in obj['requestBody']['content']):
                        if not obj.get("security"):
                            self.vulns.append(Vulnerability(
                                id="API10:2023",
                                title="Unsafe File Upload",
                                description="File upload endpoint without security.",
                                endpoint=f"{method.upper()} {path}",
                                risk="HIGH"
                            ))

    def check_owasp_top_10_patterns(self):
        # Additional rules: SSRF etc
        paths = self.spec.get("paths", {})
        for path, defs in paths.items():
            for method, obj in defs.items():
                # Heuristic: endpoints that take URLs as parameters may be SSRF-prone
                params = []
                if isinstance(obj, dict):
                    params = obj.get("parameters", [])
                for param in params:
                    if param.get("in") in {"query", "body"} and "url" in param.get("name", "").lower():
                        self.vulns.append(Vulnerability(
                            id="API7:2023",
                            title="Possible SSRF Parameter",
                            description=f"Parameter '{param.get('name')}' may allow SSRF.",
                            endpoint=f"{method.upper()} {path}",
                            risk="HIGH",
                            evidence=str(param)
                        ))

    def run_auth_tests(self, test_runner: Optional[Any] = None):
        """
        Optionally run active tests (manual driver to supply HTTP runner with given endpoints).
        Test runner should implement .run(endpoint, method, test_type) -> result
        """
        if not test_runner:
            return
        auth_issues = []
        for path, defs in self.spec.get("paths", {}).items():
            for method, obj in defs.items():
                if not isinstance(obj, dict): continue
                # Test access without credentials (expect 401/403):
                resp = test_runner.run(path, method, test_type="no_auth")
                if resp and resp.status_code < 400:
                    self.vulns.append(Vulnerability(
                        id="API2:2023",
                        title="Failed Authentication Enforcement",
                        description="Endpoint accessible with no credentials.",
                        endpoint=f"{method.upper()} {path}",
                        risk="CRITICAL",
                        evidence=f"Returned {resp.status_code}, body: {getattr(resp, 'text', '')[:100]}"
                    ))
                # Optionally test with user of wrong role/claims
                if hasattr(test_runner, "run_as_user"):
                    resp2 = test_runner.run_as_user(path, method, role="basic")
                    # If admin function available to basic user, flag
                    if re.search(r"/admin|priv|internal", path) and resp2 and resp2.status_code < 400:
                        self.vulns.append(Vulnerability(
                            id="API5:2023",
                            title="Authorization Bypass",
                            description="Privileged function accessible to unprivileged user.",
                            endpoint=f"{method.upper()} {path}",
                            risk="CRITICAL",
                            evidence=f"Returned {resp2.status_code}"
                        ))

    def run_rate_limit_tests(self, test_runner: Optional[Any] = None):
        """
        Optionally test for rate limiting if test_runner supports it.
        """
        if not test_runner:
            return
        for path, defs in self.spec.get("paths", {}).items():
            for method, obj in defs.items():
                if not isinstance(obj, dict): continue
                if getattr(test_runner, "test_rate_limit", None):
                    res = test_runner.test_rate_limit(path, method)
                    if res.get("unlimited"):
                        self.vulns.append(Vulnerability(
                            id="API4:2023",
                            title="No Rate Limiting",
                            description="Endpoint appears not to enforce any rate limiting.",
                            endpoint=f"{method.upper()} {path}",
                            risk="HIGH",
                            evidence=str(res)
                        ))

    def generate_report(self) -> Dict[str, Any]:
        return {
            "summary": {
                "total_vulnerabilities": len(self.vulns),
                "by_risk": self._risk_summary()
            },
            "vulnerabilities": [v.as_dict() for v in self.vulns]
        }

    def _risk_summary(self):
        risk_map = {}
        for v in self.vulns:
            risk = v.risk.upper()
            risk_map[risk] = risk_map.get(risk, 0) + 1
        return risk_map

    @staticmethod
    def load_openapi_from_file(filepath: str) -> Dict[str, Any]:
        with open(filepath, "r", encoding="utf-8") as f:
            if filepath.endswith(".json"):
                return json.load(f)
            # YAML support only if pyyaml present in environment
            try:
                import yaml
                return yaml.safe_load(f)
            except ImportError:
                raise ValueError("Install 'pyyaml' for YAML OpenAPI support.")

    @staticmethod
    def quick_scan_file(filepath: str) -> Dict[str, Any]:
        spec = VaultAPIScanner.load_openapi_from_file(filepath)
        scanner = VaultAPIScanner(spec)
        scanner.scan()
        return scanner.generate_report()
