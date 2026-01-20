import pytest
from unittest.mock import Mock, patch, AsyncMock
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials
from gateway.middleware import (
    AuthContext,
    authenticate_request,
    require_roles,
    require_scopes,
    get_jwt_public_key,
    get_api_key_info,
)


class TestAuthenticationMiddleware:
    """Test suite for VAULT Authentication Middleware"""

    @pytest.fixture
    def mock_request(self):
        """Create a mock FastAPI request"""
        request = Mock(spec=Request)
        request.client.host = "192.168.1.100"
        request.state = Mock()
        return request

    @pytest.fixture
    def sample_api_key_info(self):
        """Sample API key information"""
        return {"scopes": ["read", "write"], "roles": ["user", "editor"]}

    @pytest.fixture
    def sample_jwt_payload(self):
        """Sample JWT payload"""
        return {
            "sub": "user123",
            "scopes": ["admin", "read"],
            "roles": ["admin"],
            "exp": 1234567890,
        }

    def test_auth_context_creation(self):
        """Test AuthContext object creation"""
        auth = AuthContext(
            subject="user123", scopes=["read", "write"], roles=["user"], method="jwt"
        )

        assert auth.subject == "user123"
        assert auth.scopes == ["read", "write"]
        assert auth.roles == ["user"]
        assert auth.method == "jwt"

    @patch("gateway.middleware.get_api_key_info")
    async def test_authenticate_request_with_api_key(self, mock_get_info, mock_request):
        """Test authentication with valid API key"""
        mock_get_info.return_value = {"scopes": ["read", "write"], "roles": ["user"]}

        # Mock API key header dependency
        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = "test-api-key-12345"

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_bearer.return_value = None

                auth = await authenticate_request(mock_request)

                assert auth.subject == "apikey:test-api-key-12345"
                assert auth.scopes == ["read", "write"]
                assert auth.roles == ["user"]
                assert auth.method == "api_key"

    @patch("gateway.middleware.get_api_key_info")
    async def test_authenticate_request_with_invalid_api_key(
        self, mock_get_info, mock_request
    ):
        """Test authentication with invalid API key"""
        mock_get_info.return_value = None

        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = "invalid-api-key"

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_bearer.return_value = None

                with pytest.raises(HTTPException) as exc_info:
                    await authenticate_request(mock_request)

                assert exc_info.value.status_code == 401
                assert "Invalid API Key" in str(exc_info.value.detail)

    @patch("gateway.middleware.get_jwt_public_key")
    @patch("gateway.middleware.jwt.decode")
    async def test_authenticate_request_with_valid_jwt(
        self, mock_decode, mock_get_key, mock_request
    ):
        """Test authentication with valid JWT"""
        mock_get_key.return_value = "test-public-key"
        mock_decode.return_value = {
            "sub": "user123",
            "scopes": ["admin", "read"],
            "roles": ["admin"],
        }

        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = None

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_creds = Mock(spec=HTTPAuthorizationCredentials)
                mock_creds.credentials = "test-jwt-token"
                mock_bearer.return_value = mock_creds

                auth = await authenticate_request(mock_request)

                assert auth.subject == "user123"
                assert auth.scopes == ["admin", "read"]
                assert auth.roles == ["admin"]
                assert auth.method == "jwt"

    @patch("gateway.middleware.get_jwt_public_key")
    @patch("gateway.middleware.jwt.decode")
    async def test_authenticate_request_with_invalid_jwt(
        self, mock_decode, mock_get_key, mock_request
    ):
        """Test authentication with invalid JWT"""
        mock_get_key.return_value = "test-public-key"
        mock_decode.side_effect = Exception("Invalid token")

        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = None

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_creds = Mock(spec=HTTPAuthorizationCredentials)
                mock_creds.credentials = "invalid-jwt-token"
                mock_bearer.return_value = mock_creds

                with pytest.raises(HTTPException) as exc_info:
                    await authenticate_request(mock_request)

                assert exc_info.value.status_code == 401
                assert "Invalid JWT" in str(exc_info.value.detail)

    async def test_authenticate_request_missing_credentials(self, mock_request):
        """Test authentication with missing credentials"""
        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = None

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_bearer.return_value = None

                with pytest.raises(HTTPException) as exc_info:
                    await authenticate_request(mock_request)

                assert exc_info.value.status_code == 401
                assert "Credentials missing" in str(exc_info.value.detail)

    @patch("gateway.middleware.get_jwt_public_key")
    @patch("gateway.middleware.jwt.decode")
    async def test_authenticate_request_jwt_missing_subject(
        self, mock_decode, mock_get_key, mock_request
    ):
        """Test JWT authentication with missing subject"""
        mock_get_key.return_value = "test-public-key"
        mock_decode.return_value = {
            "scopes": ["read"],
            "roles": ["user"],
            # Missing "sub" field
        }

        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = None

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_creds = Mock(spec=HTTPAuthorizationCredentials)
                mock_creds.credentials = "test-jwt-token"
                mock_bearer.return_value = mock_creds

                with pytest.raises(HTTPException) as exc_info:
                    await authenticate_request(mock_request)

                assert exc_info.value.status_code == 401
                assert "JWT missing subject" in str(exc_info.value.detail)

    @patch("gateway.middleware.get_jwt_public_key")
    @patch("gateway.middleware.jwt.decode")
    async def test_authenticate_request_jwt_string_scopes(
        self, mock_decode, mock_get_key, mock_request
    ):
        """Test JWT authentication with string scopes"""
        mock_get_key.return_value = "test-public-key"
        mock_decode.return_value = {
            "sub": "user123",
            "scope": "read write admin",  # String instead of list
            "role": "user",  # String instead of list
        }

        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = None

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_creds = Mock(spec=HTTPAuthorizationCredentials)
                mock_creds.credentials = "test-jwt-token"
                mock_bearer.return_value = mock_creds

                auth = await authenticate_request(mock_request)

                assert auth.scopes == ["read", "write", "admin"]
                assert auth.roles == ["user"]

    @patch("gateway.middleware.authenticate_request")
    async def test_require_roles_success(self, mock_auth, mock_request):
        """Test role requirement checker with sufficient roles"""
        mock_auth.return_value = AuthContext(
            subject="user123", scopes=["read"], roles=["admin", "user"], method="jwt"
        )

        checker = require_roles("admin", "manager")
        result = await checker(mock_request)

        assert result.subject == "user123"
        assert "admin" in result.roles

    @patch("gateway.middleware.authenticate_request")
    async def test_require_roles_insufficient(self, mock_auth, mock_request):
        """Test role requirement checker with insufficient roles"""
        mock_auth.return_value = AuthContext(
            subject="user123", scopes=["read"], roles=["user"], method="jwt"
        )

        checker = require_roles("admin", "manager")

        with pytest.raises(HTTPException) as exc_info:
            await checker(mock_request)

        assert exc_info.value.status_code == 403
        assert "Insufficient role" in str(exc_info.value.detail)

    @patch("gateway.middleware.authenticate_request")
    async def test_require_scopes_success(self, mock_auth, mock_request):
        """Test scope requirement checker with sufficient scopes"""
        mock_auth.return_value = AuthContext(
            subject="user123",
            scopes=["read", "write", "admin"],
            roles=["user"],
            method="jwt",
        )

        checker = require_scopes("read", "write")
        result = await checker(mock_request)

        assert result.subject == "user123"
        assert all(scope in result.scopes for scope in ["read", "write"])

    @patch("gateway.middleware.authenticate_request")
    async def test_require_scopes_missing(self, mock_auth, mock_request):
        """Test scope requirement checker with missing scopes"""
        mock_auth.return_value = AuthContext(
            subject="user123", scopes=["read"], roles=["user"], method="jwt"
        )

        checker = require_scopes("admin", "write")

        with pytest.raises(HTTPException) as exc_info:
            await checker(mock_request)

        assert exc_info.value.status_code == 403
        assert "Missing required scopes" in str(exc_info.value.detail)

    def test_get_jwt_public_key_not_implemented(self):
        """Test that get_jwt_public_key raises NotImplementedError"""
        with pytest.raises(NotImplementedError):
            get_jwt_public_key()

    def test_get_api_key_info_not_implemented(self):
        """Test that get_api_key_info returns None by default"""
        result = get_api_key_info("test-key")
        assert result is None

    async def test_authenticate_request_sets_request_state(self, mock_request):
        """Test that authentication sets request state properly"""
        with patch("gateway.middleware.get_api_key_info") as mock_get_info:
            mock_get_info.return_value = {"scopes": ["read"], "roles": ["user"]}

            with patch("gateway.middleware.api_key_header") as mock_header:
                mock_header.return_value = "test-api-key-12345"

                with patch("gateway.middleware.http_bearer") as mock_bearer:
                    mock_bearer.return_value = None

                    await authenticate_request(mock_request)

                    assert hasattr(mock_request.state, "auth")
                    assert (
                        mock_request.state.auth.subject == "apikey:test-api-key-12345"
                    )

    @patch("gateway.middleware.get_jwt_public_key")
    @patch("gateway.middleware.jwt.decode")
    async def test_jwt_decode_options(self, mock_decode, mock_get_key, mock_request):
        """Test that JWT decode is called with correct options"""
        mock_get_key.return_value = "test-public-key"
        mock_decode.return_value = {
            "sub": "user123",
            "scopes": ["read"],
            "roles": ["user"],
        }

        with patch("gateway.middleware.api_key_header") as mock_header:
            mock_header.return_value = None

            with patch("gateway.middleware.http_bearer") as mock_bearer:
                mock_creds = Mock(spec=HTTPAuthorizationCredentials)
                mock_creds.credentials = "test-jwt-token"
                mock_bearer.return_value = mock_creds

                await authenticate_request(mock_request)

                mock_decode.assert_called_once_with(
                    "test-jwt-token",
                    "test-public-key",
                    algorithms=["RS256"],
                    options={"verify_aud": False},
                )
