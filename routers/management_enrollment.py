"""Enrollment health fields for the fleet management table.

Every value is read from what the client collected. A field the platform does
not report stays None so the dashboard can show it as unknown rather than as
healthy or absent.
"""

from datetime import datetime, timezone


def _bool(value):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower() if value is not None else ""
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    return None


def _first_bool(*sources):
    for source, *keys in sources:
        if not isinstance(source, dict):
            continue
        for key in keys:
            value = _bool(source.get(key))
            if value is not None:
                return value
    return None


def _iso(value):
    """Parse ISO-8601 or OpenSSL-style ('Sep 16 23:10:35 2027 GMT') timestamps to ISO UTC."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    parsed = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%b %d %H:%M:%S %Y GMT", "%b %d %H:%M:%S %Y"):
            try:
                parsed = datetime.strptime(" ".join(text.split()), fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def compliance_state(management):
    """compliant / non_compliant from a reported state or evaluated policies; else None."""
    report = (
        management.get("compliance_status")
        or management.get("complianceStatus")
        or management.get("compliance")
    )
    if isinstance(report, dict):
        overall = (
            str(report.get("overall_status") or report.get("overallStatus") or "")
            .strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
        )
        if overall in ("compliant", "non_compliant", "noncompliant"):
            return (
                "compliant" if overall == "compliant" else "non_compliant"
            ), "reported"
        flag = _bool(report.get("is_compliant", report.get("isCompliant")))
        if flag is not None:
            return ("compliant" if flag else "non_compliant"), "reported"
    policies = management.get("compliancePolicies") or management.get(
        "compliance_policies"
    )
    if isinstance(policies, list):
        flags = [
            _bool(p.get("isCompliant", p.get("is_compliant")))
            for p in policies
            if isinstance(p, dict)
        ]
        flags = [f for f in flags if f is not None]
        if flags:
            return ("compliant" if all(flags) else "non_compliant"), "policies"
    return None, None


def mdm_certificate_expiry(management, parsed_certificate):
    """MDM identity certificate expiry: macOS mdm_certificate, Windows Intune MDM device certificate."""
    if parsed_certificate:
        expiry = _iso(
            parsed_certificate.get("certificate_expires")
            or parsed_certificate.get("certificateExpires")
        )
        if expiry:
            return expiry
    metadata = management.get("metadata") or {}
    certificates = metadata.get("Certificates") if isinstance(metadata, dict) else None
    if not isinstance(certificates, list):
        return None
    details = _dict(management.get("deviceDetails") or management.get("device_details"))
    intune_id = str(
        details.get("intuneDeviceId") or details.get("intune_device_id") or ""
    ).lower()
    candidates = [
        c
        for c in certificates
        if isinstance(c, dict) and "mdm device ca" in str(c.get("Issuer") or "").lower()
    ]
    exact = [
        c
        for c in candidates
        if intune_id and str(c.get("Subject") or "").lower() == intune_id
    ]
    chosen = exact or candidates
    expiries = sorted(e for e in (_iso(c.get("NotValidAfter")) for c in chosen) if e)
    return expiries[-1] if expiries else None


UNKNOWN = {
    "complianceState": None, "complianceSource": None, "lastMdmSync": None, "mdmCertificateExpires": None,
    "userApprovedMdm": None, "installedFromDep": None, "depCapable": None,
}


def _dict(value):
    return value if isinstance(value, dict) else {}


def enrollment_fields(management, parsed_certificate, mdm_enrollment):
    """Never raises: a malformed payload reports every field as unknown."""
    try:
        return _enrollment_fields(_dict(management), _dict(parsed_certificate), _dict(mdm_enrollment))
    except Exception:
        return dict(UNKNOWN)


def _enrollment_fields(management, parsed_certificate, mdm_enrollment):
    info = _dict(management.get("mdm_info") or management.get("mdmInfo"))
    state, source = compliance_state(management)
    last_sync = _iso(
        management.get("lastSync")
        or management.get("last_sync")
        or mdm_enrollment.get("lastSync")
        or mdm_enrollment.get("last_sync")
    )
    return {
        "complianceState": state,
        "complianceSource": source,
        "lastMdmSync": last_sync,
        "mdmCertificateExpires": mdm_certificate_expiry(management, parsed_certificate),
        "userApprovedMdm": _first_bool((mdm_enrollment, "user_approved", "userApproved"), (info, "is_user_approved", "isUserApproved")),
        "installedFromDep": _first_bool((mdm_enrollment, "installed_from_dep", "installedFromDep"), (info, "enrolled_in_dep", "enrolledInDep")),
        "depCapable": _first_bool((mdm_enrollment, "dep_capable", "depCapable")),
    }
