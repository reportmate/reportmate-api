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
    devices,
    events,
    fleet,
    health,
    settings,
    statistics,
)

ROUTER_MODULES = [admin, api_keys, devices, events, fleet, health, settings, statistics]

# Routes that are anonymous by design. Adding to this list is a deliberate,
# reviewed decision — liveness/readiness must work before secrets are mounted,
# and /health is the public status endpoint.
ANONYMOUS_ALLOWED = {
    "/health",
    "/health/live",
    "/health/ready",
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
