"""Tests for security/redaction.py — ensure secrets are scrubbed from output."""

from __future__ import annotations

from server_maintenance_mcp.security.redaction import Redactor, redact, redact_output


def _r(text: str) -> str:
    return redact(text)


class TestPEMKeys:
    def test_rsa_private_key(self):
        text = "config:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\ndone"
        result = _r(text)
        assert "[REDACTED]" in result
        assert "MIIEpAIBAA" not in result
        assert "done" in result

    def test_ec_private_key(self):
        text = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----"
        result = _r(text)
        assert "MHQCAQEE" not in result

    def test_openssh_private_key(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...\n-----END OPENSSH PRIVATE KEY-----"
        result = _r(text)
        assert "b3BlbnNz" not in result


class TestCloudTokens:
    def test_aws_access_key(self):
        result = _r("key=AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_github_token(self):
        result = _r("token=ghp_1234567890abcdef1234567890abcdef1234")
        assert "ghp_1234567890abcdef1234567890abcdef1234" not in result

    def test_slack_token(self):
        result = _r("xoxb-1234567890-1234567890123-abcdef")
        assert "xoxb-1234567890" not in result

    def test_google_api_key(self):
        result = _r("AIzaSyD1234567890abcdefghijklmnopqrstuvwxyz12")
        assert "AIzaSyD" not in result


class TestPasswordAssignments:
    def test_password_equals(self):
        result = _r("password=s3cr3t")
        assert "s3cr3t" not in result
        assert "[REDACTED]" in result

    def test_password_colon(self):
        result = _r("DB_PASSWORD: mysecret123")
        assert "mysecret123" not in result

    def test_api_key_assignment(self):
        result = _r("api_key: ABC123XYZ")
        assert "ABC123XYZ" not in result

    def test_passwd_colon(self):
        result = _r("passwd: hunter2")
        assert "hunter2" not in result

    def test_secret_with_dashes(self):
        result = _r("client-secret=abc123def456")
        assert "abc123def456" not in result


class TestConnectionStrings:
    def test_postgres_url(self):
        result = _r("postgres://user:p4ssw0rd@localhost:5432/db")
        assert "p4ssw0rd" not in result
        assert "localhost:5432" in result or "localhost" in result

    def test_mysql_url(self):
        result = _r("mysql://admin:admin@10.0.0.1/mydb")
        assert "admin:admin@" not in result

    def test_redis_url(self):
        result = _r("redis://default:secretpass@redis:6379")
        assert "secretpass" not in result


class TestJWT:
    def test_jwt_token(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4f"
        result = _r(token)
        assert "SflKxw" not in result


class TestBearerTokens:
    def test_bearer_in_header(self):
        result = _r("Authorization: Bearer eyJhbGciOi.eyJzdWIiOi.SflKxw")
        assert "eyJhbGci" not in result


class TestCreditCards:
    def test_visa_number(self):
        result = _r("Card: 4111-1111-1111-1111")
        assert "4111-1111-1111-1111" not in result


class TestDoesNotOverRedact:
    def test_normal_text_preserved(self):
        text = "systemd[1]: Started nginx.service. Status: active (running)"
        assert _r(text) == text

    def test_service_name_preserved(self):
        text = "● nginx.service - The nginx HTTP and reverse proxy server"
        assert "nginx.service" in _r(text)

    def test_ip_address_preserved(self):
        text = "listening on 192.168.1.100:80"
        assert "192.168.1.100" in _r(text)

    def test_username_in_log_preserved(self):
        text = "Accepted publickey for admin from 10.0.0.1"
        assert "admin" in _r(text)

    def test_normal_path_preserved(self):
        text = "Reading /var/log/syslog for errors"
        assert _r(text) == text


class TestRedactOutputDecorator:
    def test_sync_function(self):
        @redact_output
        def tool() -> str:
            return "password=hunter2 status=ok"

        result = tool()
        assert "hunter2" not in result
        assert "status=ok" in result

    async def test_async_function(self):
        @redact_output
        async def tool() -> str:
            return "api_key=sk_test_12345 done=true"

        result = await tool()
        assert "sk_test_12345" not in result
        assert "done=true" in result

    async def test_async_list_output(self):
        @redact_output
        async def tool() -> list[str]:
            return ["password=secret1", "status=ok"]

        result = await tool()
        assert "secret1" not in result[0]
        assert result[1] == "status=ok"

    def test_dict_output(self):
        @redact_output
        def tool() -> dict:
            return {"token": "ghp_1234567890abcdef1234567890abcdef1234", "status": "ok"}

        result = tool()
        assert "ghp_1234567890abcdef1234567890abcdef1234" not in result["token"]
        assert result["status"] == "ok"

    def test_non_string_output_preserved(self):
        @redact_output
        def tool() -> int:
            return 42

        assert tool() == 42
