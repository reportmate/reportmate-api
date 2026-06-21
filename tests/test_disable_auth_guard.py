"""The DISABLE_AUTH escape hatch must not be usable in production.

assert_auth_enabled_for_prod() is the startup guard; it reads module-level
globals, so each case monkeypatches them directly.
"""

import dependencies
import pytest
from dependencies import assert_auth_enabled_for_prod


def _set(monkeypatch, *, disable, app_env="", passphrase=None, internal=None):
    monkeypatch.setattr(dependencies, "DISABLE_AUTH", disable)
    monkeypatch.setattr(dependencies, "APP_ENV", app_env)
    monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", passphrase)
    monkeypatch.setattr(dependencies, "API_INTERNAL_SECRET", internal)


def test_auth_enabled_always_passes(monkeypatch):
    # DISABLE_AUTH off -> never blocks, regardless of env/secrets.
    _set(monkeypatch, disable=False, app_env="production", passphrase="x")
    assert_auth_enabled_for_prod()  # no raise


def test_disabled_with_secrets_is_refused(monkeypatch):
    # Production-like by virtue of configured secrets, no explicit env.
    _set(monkeypatch, disable=True, app_env="", passphrase="real-secret")
    with pytest.raises(RuntimeError, match="DISABLE_AUTH"):
        assert_auth_enabled_for_prod()


def test_disabled_with_prod_app_env_is_refused(monkeypatch):
    _set(monkeypatch, disable=True, app_env="production", passphrase=None)
    with pytest.raises(RuntimeError):
        assert_auth_enabled_for_prod()


def test_disabled_with_staging_app_env_is_refused(monkeypatch):
    _set(monkeypatch, disable=True, app_env="staging", passphrase=None)
    with pytest.raises(RuntimeError):
        assert_auth_enabled_for_prod()


def test_disabled_in_explicit_development_is_allowed(monkeypatch):
    # The deliberate local escape hatch: explicit dev env, even with secrets set.
    _set(monkeypatch, disable=True, app_env="development", passphrase="local")
    assert_auth_enabled_for_prod()  # no raise


def test_disabled_pure_dev_no_env_no_secrets_is_allowed(monkeypatch):
    # Nothing indicates production: no env marker, no secrets -> allowed.
    _set(monkeypatch, disable=True, app_env="", passphrase=None, internal=None)
    assert_auth_enabled_for_prod()  # no raise
