"""The OpenAPI spec must document how to authenticate."""

from main import app


def test_security_schemes_documented():
    schema = app.openapi()
    schemes = schema["components"]["securitySchemes"]
    assert set(schemes) == {"ApiKeyAuth", "ClientPassphrase", "BearerAuth"}
    assert schemes["ApiKeyAuth"] == {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": schemes["ApiKeyAuth"]["description"],
    }
    assert schemes["BearerAuth"]["scheme"] == "bearer"


def test_global_security_requirement_present():
    schema = app.openapi()
    reqs = {list(r)[0] for r in schema["security"]}
    assert reqs == {"ApiKeyAuth", "ClientPassphrase", "BearerAuth"}
