"""Read-only fleet sign-in and recovery posture: one row per device.

Every check is three-valued. A value the client did not send, sent in an
unexpected shape, or sent longer ago than the maximum collection age is
unknown, never false. Only explicit collected evidence can put a device in a
quick view.
"""

from collections import Counter
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from dependencies import (
    get_db_connection,
    infer_platform,
    load_sql,
    logger,
    verify_authentication,
)
from routers.system_services import _list, _platform, collection_freshness

router = APIRouter(tags=["fleet"])

QUICK_VIEWS = (
    "noLaps",
    "autoLogin",
    "expiredPssoToken",
    "activationLock",
    "noRecoveryKey",
)
VIEW_PLATFORM = {
    "noLaps": "Windows",
    "autoLogin": "Windows",
    "expiredPssoToken": "macOS",
    "activationLock": "macOS",
    "noRecoveryKey": "macOS",
}
SCOPES = {
    "usages": "usage",
    "catalogs": "catalog",
    "areas": "area",
    "fleets": "fleet",
    "locations": "location",
    "rooms": "room",
}


def tri(value):
    """Collected boolean as True, False or None. Clients send bools, 0/1 or strings."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    text = str(value).strip().lower() if isinstance(value, str) else ""
    if text in ("true", "yes", "1", "enabled", "on"):
        return True
    if text in ("false", "no", "0", "disabled", "off"):
        return False
    return None


def number(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _obj(value):
    return value if isinstance(value, dict) else {}


def text(value):
    """Collected text, or None for anything that is not a nonempty string."""
    return value.strip() or None if isinstance(value, str) else None


def _time(value):
    if not value or not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result
    except ValueError:
        return None


def laps_state(laps):
    """Windows LAPS or legacy LAPS policy present on the device."""
    if not isinstance(laps, dict):
        return "unknown"
    win, legacy = tri(laps.get("windowsLapsConfigured")), tri(
        laps.get("legacyLapsInstalled")
    )
    if win or legacy:
        return "configured"
    return "not_configured" if win is False and legacy is False else "unknown"


def activation_lock_state(lock):
    status = str(_obj(lock).get("status") or "").strip().lower()
    return {"enabled": "on", "likely enabled": "likely", "disabled": "off"}.get(
        status, "unknown"
    )


def recovery_key_state(file_vault):
    """Whether a FileVault personal or institutional recovery key exists on the device."""
    if not isinstance(file_vault, dict):
        return "unknown"
    enabled = tri(file_vault.get("enabled"))
    if enabled is False:
        return "filevault_off"
    prk, irk = tri(file_vault.get("personalRecoveryKey")), tri(
        file_vault.get("institutionalRecoveryKey")
    )
    if prk or irk:
        return "present"
    if enabled and prk is False and irk is False:
        return "none"
    return "unknown"


def psso_users(platform_sso, now):
    """Per-user Platform SSO token state, judged against the report time, not collection time."""
    users = []
    users_raw = _obj(platform_sso).get("users")
    for user in users_raw if isinstance(users_raw, list) else []:
        if not isinstance(user, dict):
            continue
        registered = tri(user.get("registered"))
        expires = _time(user.get("tokenExpiration"))
        reported_expired = tri(user.get("tokenExpired"))
        if registered is not True:
            token = "not_registered" if registered is False else "unknown"
        elif expires is not None:
            token = "expired" if expires <= now else "valid"
        elif reported_expired is not None:
            token = "expired" if reported_expired else "valid"
        else:
            token = "unknown"
        users.append(
            {
                "username": text(user.get("username")),
                "registered": registered,
                "tokenExpiration": text(user.get("tokenExpiration")),
                "token": token,
            }
        )
    return users


def psso_state(platform_sso, users):
    if not isinstance(platform_sso, dict):
        return "unknown"
    registered = [u for u in users if u["registered"] is True]
    if any(u["token"] == "expired" for u in registered):
        return "expired"
    if registered:
        return "valid" if all(u["token"] == "valid" for u in registered) else "unknown"
    device = tri(platform_sso.get("deviceRegistered"))
    if device is False:
        return "not_registered"
    return "no_registered_users" if device else "unknown"


def shape_device(row, now, max_age_hours):
    row = dict(row)
    windows, mac = _obj(row.pop("windows", None)), _obj(row.pop("mac", None))
    platform = infer_platform(text(row.get("platform"))) or text(row.get("platform")) or "Unknown"
    row["platform"] = platform
    row["identityFreshness"] = (
        collection_freshness(row.get("identityCollectedAt"), now, max_age_hours)
        if row.get("identityReported")
        else "unknown"
    )
    row["securityFreshness"] = (
        collection_freshness(row.get("securityCollectedAt"), now, max_age_hours)
        if row.get("securityReported")
        else "unknown"
    )
    reported = {}
    if platform == "Windows":
        auto, uac, policy = (
            _obj(windows.get("autoLogin")),
            _obj(windows.get("uac")),
            _obj(windows.get("passwordPolicy")),
        )
        providers, guard, tpm = (
            _obj(windows.get("credentialProviders")),
            _obj(windows.get("credentialGuard")),
            _obj(windows.get("tpmOwnership")),
        )
        policy_ok = bool(policy) and not policy.get("errorMessage")
        reported = {
            "laps": laps_state(windows.get("laps")),
            "lapsBackupDirectory": text(_obj(windows.get("laps")).get("backupDirectory")),
            "autoLogin": tri(auto.get("autoAdminLogon")),
            "autoLoginStoredPassword": tri(auto.get("hasDefaultPassword")),
            "uacEnabled": tri(uac.get("enableLua")),
            "uacLevel": text(uac.get("level")),
            "minPasswordLength": (
                number(policy.get("minPasswordLength")) if policy_ok else None
            ),
            "maxPasswordAgeDays": (
                number(policy.get("maxPasswordAgeDays")) if policy_ok else None
            ),
            "passwordHistoryLength": (
                number(policy.get("passwordHistoryLength")) if policy_ok else None
            ),
            "lockoutThreshold": (
                number(policy.get("lockoutThreshold")) if policy_ok else None
            ),
            "lockoutDurationMinutes": (
                number(policy.get("lockoutDurationMinutes")) if policy_ok else None
            ),
            "helloStatus": (
                windows.get("helloStatus")
                if isinstance(windows.get("helloStatus"), str)
                and windows.get("helloStatus")
                else None
            ),
            "helloProviders": (
                None
                if not providers
                else [
                    label
                    for key, label in (
                        ("pinEnabled", "PIN"),
                        ("fingerprintEnabled", "Fingerprint"),
                        ("faceRecognitionEnabled", "Face"),
                        ("smartCardEnabled", "Smart card"),
                    )
                    if tri(providers.get(key))
                ]
            ),
            "credentialGuard": tri(guard.get("isEnabled")),
            "tpmOwned": tri(tpm.get("isOwned")),
            "tpmReady": tri(tpm.get("isReady")),
            "failedLoginsLast7Days": number(windows.get("failedLoginsLast7Days")),
        }
    elif platform == "macOS":
        platform_sso = mac.get("platformSSO")
        users = psso_users(platform_sso, now)
        secure, bootstrap, lock, vault = (
            _obj(mac.get("secureToken")),
            _obj(mac.get("bootstrapToken")),
            _obj(mac.get("activationLock")),
            _obj(mac.get("fileVault")),
        )
        reported = {
            "pssoState": psso_state(platform_sso, users),
            "pssoProvider": text(_obj(platform_sso).get("provider")),
            "pssoUsers": users,
            "secureTokenGranted": number(secure.get("tokenGrantedCount")),
            "secureTokenMissing": number(secure.get("tokenMissingCount")),
            "bootstrapTokenEscrowed": tri(bootstrap.get("escrowed")),
            "activationLock": activation_lock_state(mac.get("activationLock")),
            "findMy": tri(lock.get("findMyMac")),
            "fileVault": tri(vault.get("enabled")),
            "personalRecoveryKey": tri(vault.get("personalRecoveryKey")),
            "institutionalRecoveryKey": tri(vault.get("institutionalRecoveryKey")),
            "recoveryKey": recovery_key_state(mac.get("fileVault")),
        }
    row["reported"] = reported
    row["checks"] = posture_checks(
        platform, reported, row["identityFreshness"], row["securityFreshness"]
    )
    return row


SECURITY_SOURCED = {"activationLock", "noRecoveryKey"}


def posture_checks(platform, reported, identity_freshness, security_freshness):
    """Quick-view membership per device: True, False, or None when unknown or not applicable.

    Stale or missing collection is unknown even when an old value was reported.
    """
    checks = {}
    for view in QUICK_VIEWS:
        if VIEW_PLATFORM[view] != platform:
            checks[view] = None
            continue
        fresh = (
            security_freshness if view in SECURITY_SOURCED else identity_freshness
        ) == "fresh"
        if view == "noLaps":
            value = {"not_configured": True, "configured": False}.get(
                reported.get("laps")
            )
        elif view == "autoLogin":
            value = reported.get("autoLogin")
        elif view == "expiredPssoToken":
            value = {
                "expired": True,
                "valid": False,
                "not_registered": False,
                "no_registered_users": False,
            }.get(reported.get("pssoState"))
        elif view == "activationLock":
            value = {"on": True, "likely": True, "off": False}.get(
                reported.get("activationLock")
            )
        else:
            value = {"none": True, "present": False, "filevault_off": True}.get(
                reported.get("recoveryKey")
            )
        checks[view] = value if fresh else None
    return checks


def unreadable_device(raw):
    raw = _obj(raw)
    row = {key: raw.get(key) for key in ("serialNumber", "deviceName", "computerName", "assetTag", "usage",
                                          "catalog", "area", "fleet", "location", "room", "archived",
                                          "inventoryState", "lastSeen")}
    row["platform"] = infer_platform(text(raw.get("platform"))) or "Unknown"
    row.update({"identityFreshness": "unknown", "securityFreshness": "unknown", "reported": {},
                "checks": {view: None for view in QUICK_VIEWS}, "unreadable": True})
    return row


def shape_posture(rows, *, views, freshness, search, max_age_hours, limit, offset, now):
    summary, unknown = Counter(), Counter()
    results = []
    for raw in rows:
        try:
            row = shape_device(raw, now, max_age_hours)
        except Exception:
            # One malformed payload shows as unknown rather than failing the report.
            row = unreadable_device(raw)
        if (
            search
            and search
            not in " ".join(
                str(row.get(k) or "")
                for k in ("deviceName", "computerName", "serialNumber", "assetTag")
            ).lower()
        ):
            continue
        if freshness != "all" and row["identityFreshness"] != freshness:
            continue
        for view, value in row["checks"].items():
            if value is True:
                summary[view] += 1
            elif value is None and VIEW_PLATFORM[view] == row["platform"]:
                unknown[view] += 1
        if any(row["checks"].get(view) is not True for view in views):
            continue
        results.append(row)
    return {
        "generatedAt": now.isoformat(),
        "maxAgeHours": max_age_hours,
        "total": len(results),
        "limit": limit,
        "offset": offset,
        "summary": {view: summary[view] for view in QUICK_VIEWS},
        "unknown": {view: unknown[view] for view in QUICK_VIEWS},
        "devices": results[offset : offset + limit],
    }


@router.get("/identity/posture", dependencies=[Depends(verify_authentication)])
def get_identity_posture(
    views: str = Query(
        default="",
        max_length=200,
        description="Quick views, comma separated; a device must match every one",
    ),
    freshness: Literal["all", "fresh", "stale", "unknown"] = "all",
    max_age_hours: int = Query(default=168, ge=1, le=8760, alias="maxAgeHours"),
    platform: str = Query(default="", max_length=30),
    search: str = Query(default="", max_length=200),
    usages: str = Query(default="", max_length=500),
    catalogs: str = Query(default="", max_length=500),
    areas: str = Query(default="", max_length=1000),
    fleets: str = Query(default="", max_length=1000),
    locations: str = Query(default="", max_length=1000),
    rooms: str = Query(default="", max_length=1000),
    inventory_states: str = Query(default="", max_length=100, alias="inventoryStates"),
    include_archived: bool = Query(default=False, alias="includeArchived"),
    limit: int = Query(default=500, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """One row per device with the sign-in and recovery posture it last reported.

    Windows: LAPS policy, auto-login, UAC, local password and lockout policy,
    Windows Hello, Credential Guard, TPM ownership, failed sign-ins in seven days.
    macOS: Platform SSO registration and per-user token expiry, Secure Token,
    Bootstrap Token, Activation Lock, Find My, FileVault recovery keys.
    """
    selected_views = [v.strip() for v in views.split(",") if v.strip()]
    if set(selected_views) - set(QUICK_VIEWS):
        raise HTTPException(status_code=422, detail="Invalid quick view")
    normalized_platform = _platform(platform)
    requested = {"usages": usages, "catalogs": catalogs, "areas": areas, "fleets": fleets,
                 "locations": locations, "rooms": rooms}
    selected = {field: _list(requested[key]) for key, field in SCOPES.items()}
    states = _list(inventory_states)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            load_sql("devices/identity_posture"),
            {
                "include_archived": include_archived,
                "platform": normalized_platform,
            },
        )
        rows = [row[0] for row in cursor.fetchall() if isinstance(row[0], dict)]
        scoped = [
            row
            for row in rows
            if all(
                not values or str(row.get(field) or "").lower() in values
                for field, values in selected.items()
            )
            and (
                not states or str(row.get("inventoryState") or "unknown").lower() in states
            )
        ]
        result = shape_posture(
            scoped,
            views=selected_views,
            freshness=freshness,
            search=search.strip().lower(),
            max_age_hours=max_age_hours,
            limit=limit,
            offset=offset,
            now=datetime.now(timezone.utc),
        )
        # Facets stay available when a scope is narrowed to zero devices.
        result["options"] = {
            key: sorted({str(row[field]) for row in rows if row.get(field)}, key=str.lower)
            for key, field in SCOPES.items()
        }
        result["options"]["inventoryStates"] = sorted(
            {str(row.get("inventoryState") or "unknown") for row in rows}
        )
        return result
    except HTTPException:
        raise
    except Exception:
        logger.exception("Identity posture report failed")
        raise HTTPException(
            status_code=500, detail="Identity posture report unavailable"
        )
    finally:
        conn.close()
