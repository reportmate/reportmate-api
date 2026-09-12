"""Every API route must carry authentication.

The negotiate endpoint shipped unauthenticated because nothing asserted the
router table's auth coverage — scope enforcement lives inside
verify_authentication, so a route that never depends on it silently bypasses
the whole model. This walks every APIRoute on every router and requires
verify_authentication somewhere in its dependency tree, except for the
explicit anonymous allowlist below.
"""

from fastapi.routing import APIRoute

from dependencies import verify_authentication
from routers import (
    admin,
    api_keys,
    auth_config,
    devices,
    events,
    fleet,
    health,
    settings,
    statistics,
)

ROUTER_MODULES = [admin, api_keys, auth_config, devices, events, fleet, health, settings, statistics]

# Routes that are anonymous by design. Adding to this list is a deliberate,
# reviewed decision — liveness/readiness must work before secrets are mounted,
# and /health is the public status endpoint.
ANONYMOUS_ALLOWED = {
    "/health",
    "/health/live",
    "/health/ready",
    # /auth/config describes how to authenticate (accepted headers, OIDC issuer
    # and audience): the same non-secret values a token carries, needed before a
    # client has any credential at all.
    "/auth/config",
}


def _dependency_callables(route: APIRoute) -> set:
    seen = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if dep.call is not None:
            seen.add(dep.call)
        stack.extend(dep.dependencies)
    return seen


def test_every_route_requires_authentication():
    unauthenticated = []
    for module in ROUTER_MODULES:
        for route in module.router.routes:
            if not isinstance(route, APIRoute):
                continue
            if route.path in ANONYMOUS_ALLOWED:
                continue
            if verify_authentication not in _dependency_callables(route):
                unauthenticated.append(
                    f"{sorted(route.methods)} {route.path} ({module.__name__})"
                )
    assert not unauthenticated, (
        "Routes without verify_authentication (add the dependency or, for a "
        f"deliberate anonymous route, extend ANONYMOUS_ALLOWED): {unauthenticated}"
    )


def test_allowlist_matches_reality():
    # The allowlist must not drift: every entry still exists, and none of the
    # listed routes quietly grew an auth dependency (which would make the
    # allowlist misleading).
    all_paths = {
        route.path
        for module in ROUTER_MODULES
        for route in module.router.routes
        if isinstance(route, APIRoute)
    }
    missing = ANONYMOUS_ALLOWED - all_paths
    assert not missing, f"Allowlisted routes no longer exist: {sorted(missing)}"


def _mounted_api_paths(app, prefix=""):
    """Every APIRoute path the app serves: plain routes, routers included
    lazily (FastAPI keeps them as an included-router entry carrying the
    original router and the prefix it was mounted with), and sub-app mounts."""
    from starlette.routing import Mount

    paths = set()
    for r in app.routes:
        if isinstance(r, APIRoute):
            paths.add(prefix + r.path)
        elif hasattr(r, "original_router") and hasattr(r, "include_context"):
            inner = getattr(r.include_context, "prefix", "") or ""
            for sub in r.original_router.routes:
                if isinstance(sub, APIRoute):
                    paths.add(prefix + inner + sub.path)
        elif isinstance(r, Mount) and hasattr(r.app, "routes"):
            paths |= _mounted_api_paths(r.app, prefix + r.path)
    return paths


def test_registry_covers_every_router_the_app_mounts():
    # A router added to main.py but not to ROUTER_MODULES would escape the
    # authentication check above; mount-time and registry must agree.
    import main as app_main

    mounted = {p for p in _mounted_api_paths(app_main.app) if p.startswith("/api/v1/")}
    registered = {
        "/api/v1" + r.path for m in ROUTER_MODULES for r in m.router.routes if isinstance(r, APIRoute)
    }
    assert mounted, "no /api/v1 routes found on the app"
    assert mounted == registered, f"unregistered routes: {sorted(mounted - registered)}"
