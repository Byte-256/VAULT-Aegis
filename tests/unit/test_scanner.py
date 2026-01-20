import pytest
import json
from unittest.mock import Mock, patch
from scanner.scanner import VaultAPIScanner, Vulnerability


class TestVaultAPIScanner:
    """Test suite for VAULT API Scanner"""

    @pytest.fixture
    def sample_openapi_spec(self):
        """Sample OpenAPI spec for testing"""
        return {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "servers": [{"url": "http://api.example.com"}],
            "paths": {
                "/public/data": {
                    "get": {
                        "summary": "Get public data",
                        "responses": {"200": {"description": "Success"}},
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user by ID",
                        "security": [],
                        "parameters": [
                            {
                                "name": "id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "Success"}},
                    }
                },
                "/admin/users": {
                    "delete": {
                        "summary": "Delete user",
                        "security": [],
                        "responses": {"200": {"description": "Success"}},
                    }
                },
                "/upload": {
                    "post": {
                        "summary": "Upload file",
                        "security": [],
                        "requestBody": {
                            "content": {
                                "multipart/form-data": {"schema": {"type": "object"}}
                            }
                        },
                        "responses": {"200": {"description": "Success"}},
                    }
                },
                "/proxy": {
                    "get": {
                        "summary": "Proxy request",
                        "parameters": [
                            {"name": "url", "in": "query", "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "Success"}},
                    }
                },
            },
        }

    @pytest.fixture
    def scanner(self, sample_openapi_spec):
        """Create scanner instance with sample spec"""
        return VaultAPIScanner(sample_openapi_spec)

    def test_scanner_initialization(self, sample_openapi_spec):
        """Test scanner initialization"""
        scanner = VaultAPIScanner(sample_openapi_spec)
        assert scanner.spec == sample_openapi_spec
        assert scanner.vulns == []

    def test_vulnerability_creation(self):
        """Test vulnerability object creation"""
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

    def test_check_auth_missing_security(self, scanner):
        """Test detection of missing authentication"""
        scanner.check_auth()

        # Should detect missing global security
        auth_vulns = [v for v in scanner.vulns if v.id == "API2:2023"]
        assert len(auth_vulns) > 0

        # Should detect endpoints without security
        endpoint_vulns = [v for v in auth_vulns if "GET /users/{id}" in v.endpoint]
        assert len(endpoint_vulns) > 0

    def test_check_authorization_object_level(self, scanner):
        """Test detection of broken object level authorization"""
        scanner.check_authorization()

        # Should detect object-level endpoints without security
        obj_vulns = [v for v in scanner.vulns if v.id == "API1:2023"]
        assert len(obj_vulns) > 0

        # Should detect admin endpoints without security
        admin_vulns = [v for v in scanner.vulns if v.id == "API5:2023"]
        assert len(admin_vulns) > 0

    def test_check_rate_limits_missing(self, scanner):
        """Test detection of missing rate limits"""
        scanner.check_rate_limits()

        # Should detect missing rate limiting
        rate_vulns = [v for v in scanner.vulns if v.id == "API4:2023"]
        assert len(rate_vulns) > 0

    def test_check_misconfigurations(self, scanner):
        """Test detection of security misconfigurations"""
        scanner.check_misconfigurations()

        # Should detect HTTP usage
        http_vulns = [
            v for v in scanner.vulns if "Insecure Transport Protocol" in v.title
        ]
        assert len(http_vulns) > 0

    def test_check_unsafe_endpoints(self, scanner):
        """Test detection of unsafe endpoints"""
        scanner.check_unsafe_endpoints()

        # Should detect unsafe HTTP methods
        unsafe_vulns = [v for v in scanner.vulns if v.id == "API10:2023"]
        assert len(unsafe_vulns) > 0

        # Should detect file upload without security
        upload_vulns = [v for v in unsafe_vulns if "Unsafe File Upload" in v.title]
        assert len(upload_vulns) > 0

    def test_check_owasp_top_10_patterns(self, scanner):
        """Test detection of OWASP Top 10 patterns"""
        scanner.check_owasp_top_10_patterns()

        # Should detect potential SSRF
        ssrf_vulns = [v for v in scanner.vulns if v.id == "API7:2023"]
        assert len(ssrf_vulns) > 0

    def test_full_scan(self, scanner):
        """Test complete scan functionality"""
        scanner.scan()

        # Should detect multiple vulnerability types
        vuln_types = set(v.id for v in scanner.vulns)
        assert len(vuln_types) > 3  # Should detect various vulnerability types

    def test_generate_report(self, scanner):
        """Test report generation"""
        scanner.scan()
        report = scanner.generate_report()

        assert "summary" in report
        assert "vulnerabilities" in report
        assert report["summary"]["total_vulnerabilities"] == len(scanner.vulns)
        assert "by_risk" in report["summary"]

    def test_risk_summary(self, scanner):
        """Test risk summary calculation"""
        # Add some test vulnerabilities
        scanner.vulns = [
            Vulnerability("TEST1", "Test 1", "desc", "/test1", "HIGH"),
            Vulnerability("TEST2", "Test 2", "desc", "/test2", "HIGH"),
            Vulnerability("TEST3", "Test 3", "desc", "/test3", "MEDIUM"),
            Vulnerability("TEST4", "Test 4", "desc", "/test4", "LOW"),
        ]

        risk_summary = scanner._risk_summary()
        assert risk_summary["HIGH"] == 2
        assert risk_summary["MEDIUM"] == 1
        assert risk_summary["LOW"] == 1

    @patch("scanner.scanner.VaultAPIScanner.load_openapi_from_file")
    def test_load_openapi_from_file_json(self, mock_load):
        """Test loading OpenAPI spec from JSON file"""
        test_spec = {"openapi": "3.0.0", "info": {"title": "Test"}}
        mock_load.return_value = test_spec

        result = VaultAPIScanner.load_openapi_from_file("test.json")
        assert result == test_spec

    @patch("scanner.scanner.VaultAPIScanner.load_openapi_from_file")
    def test_quick_scan_file(self, mock_load):
        """Test quick scan functionality"""
        test_spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API"},
            "paths": {
                "/test": {
                    "get": {"security": [], "responses": {"200": {"description": "OK"}}}
                }
            },
        }
        mock_load.return_value = test_spec

        report = VaultAPIScanner.quick_scan_file("test.json")
        assert "summary" in report
        assert "vulnerabilities" in report

    def test_run_auth_tests_no_runner(self, scanner):
        """Test auth tests with no runner"""
        # Should not raise exception
        scanner.run_auth_tests(None)
        assert len(scanner.vulns) == 0

    def test_run_rate_limit_tests_no_runner(self, scanner):
        """Test rate limit tests with no runner"""
        # Should not raise exception
        scanner.run_rate_limit_tests(None)
        assert len(scanner.vulns) == 0

    def test_run_auth_tests_with_mock_runner(self, scanner):
        """Test auth tests with mock runner"""
        mock_runner = Mock()
        mock_runner.run.return_value = Mock(status_code=200, text="OK")

        scanner.run_auth_tests(mock_runner)

        # Should detect failed authentication enforcement
        auth_vulns = [
            v for v in scanner.vulns if "Failed Authentication Enforcement" in v.title
        ]
        assert len(auth_vulns) > 0
