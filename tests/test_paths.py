"""Tests for security/paths.py — ensure sensitive paths are blocked."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from server_maintenance_mcp.security.paths import PathGuard, PathValidationError


@pytest.fixture
def tmp_allowed_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d).resolve()


@pytest.fixture
def guard(tmp_allowed_dir):
    return PathGuard(allowed_dirs=[str(tmp_allowed_dir)])


@pytest.fixture
def log_file(tmp_allowed_dir):
    f = tmp_allowed_dir / "app.log"
    f.write_text("line1\nline2\n")
    return f


class TestAllowedPaths:
    def test_allowed_file_access(self, guard, log_file):
        result = guard.validate(str(log_file))
        assert result == log_file.resolve()

    def test_allowed_subdirectory(self, guard, tmp_allowed_dir):
        subdir = tmp_allowed_dir / "sub" / "deep"
        subdir.mkdir(parents=True)
        f = subdir / "nested.log"
        f.write_text("data")
        result = guard.validate(str(f))
        assert result == f.resolve()


class TestForbiddenPaths:
    def test_ssh_dir_blocked(self, guard, tmp_allowed_dir):
        ssh_path = tmp_allowed_dir / ".ssh" / "id_rsa"
        ssh_path.parent.mkdir(parents=True)
        ssh_path.write_text("key")
        with pytest.raises(PathValidationError, match="protected directory|forbidden"):
            guard.validate(str(ssh_path))

    def test_pem_file_blocked(self, guard, tmp_allowed_dir):
        pem_file = tmp_allowed_dir / "server.pem"
        pem_file.write_text("fake key")
        with pytest.raises(PathValidationError, match="forbidden"):
            guard.validate(str(pem_file))

    def test_env_file_blocked(self, guard, tmp_allowed_dir):
        env_file = tmp_allowed_dir / "config.env"
        env_file.write_text("SECRET=xxx")
        with pytest.raises(PathValidationError, match="forbidden"):
            guard.validate(str(env_file))

    def test_dotenv_blocked(self, guard, tmp_allowed_dir):
        dotenv = tmp_allowed_dir / ".env"
        dotenv.write_text("SECRET=xxx")
        with pytest.raises(PathValidationError, match="forbidden"):
            guard.validate(str(dotenv))

    def test_credential_filename_blocked(self, guard, tmp_allowed_dir):
        cred_file = tmp_allowed_dir / "credentials.json"
        cred_file.write_text("{}")
        with pytest.raises(PathValidationError, match="forbidden"):
            guard.validate(str(cred_file))

    def test_authorized_keys_blocked(self, guard, tmp_allowed_dir):
        ak = tmp_allowed_dir / "authorized_keys"
        ak.write_text("ssh-rsa AAAA...")
        with pytest.raises(PathValidationError, match="forbidden"):
            guard.validate(str(ak))

    def test_id_rsa_blocked(self, guard, tmp_allowed_dir):
        key = tmp_allowed_dir / "id_rsa"
        key.write_text("priv key")
        with pytest.raises(PathValidationError, match="forbidden"):
            guard.validate(str(key))

    def test_shadow_file_blocked(self, guard):
        if not os.path.exists("/etc/shadow"):
            pytest.skip("/etc/shadow does not exist on this system")
        with pytest.raises(PathValidationError, match="forbidden"):
            guard.validate("/etc/shadow")


class TestPathTraversal:
    def test_dotdot_outside_allowed(self, guard, tmp_allowed_dir, log_file):
        traversal = str(log_file) + "/../../etc/shadow"
        with pytest.raises(PathValidationError):
            guard.validate(traversal)

    def test_absolute_path_outside_allowed(self, guard):
        if os.path.exists("/etc/hostname"):
            with pytest.raises(PathValidationError, match="not in allowed"):
                guard.validate("/etc/hostname")


class TestEdgeCases:
    def test_empty_path_rejected(self, guard):
        with pytest.raises(PathValidationError):
            guard.validate("")

    def test_nonexistent_file(self, guard, tmp_allowed_dir):
        with pytest.raises(PathValidationError, match="not found"):
            guard.validate(str(tmp_allowed_dir / "nonexistent.log"))

    def test_directory_not_file(self, guard, tmp_allowed_dir):
        with pytest.raises(PathValidationError, match="Not a regular file"):
            guard.validate(str(tmp_allowed_dir))

    def test_symlink_escape_blocked(self, guard, tmp_allowed_dir):
        outside = tempfile.mkdtemp()
        try:
            target = Path(outside) / "secret.log"
            target.write_text("sensitive")
            link = tmp_allowed_dir / "link.log"
            link.symlink_to(target)
            with pytest.raises(PathValidationError):
                guard.validate(str(link))
        finally:
            import shutil
            shutil.rmtree(outside)

    def test_non_string_rejected(self, guard):
        with pytest.raises(PathValidationError):
            guard.validate(None)  # type: ignore[arg-type]
