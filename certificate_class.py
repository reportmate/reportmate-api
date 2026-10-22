"""One definition of which certificates an admin can act on.

A device reports every certificate its stores and keychains hold, and almost
none of them are anyone's job. Windows lists the same trust-store roots once per
logical store view (machine, each user hive, each service account), Entra-joined
devices carry peer-to-peer certificates that expire within a day and rotate
themselves, the MDM agents hold identity certificates they renew on their own,
and a Mac's login keychain keeps copies of every signed email's certificate and
every server certificate the user accepted. Counting all of them made every
certificate number on the dashboard and the security report wrong.

Each certificate gets one of three classes, decided here and stamped on the
certificate at ingest so the API, the web, the Mac app and the Windows app all
read the same answer:

``actionable``
    Certificates someone has to renew: identities issued by the organisation's
    PKI or deployed by a profile or policy, app-installed certificates in the
    personal stores, and roots or intermediates the organisation deployed by
    policy (an expiring enterprise root is the most actionable certificate there
    is).
``system-managed``
    Certificates the OS or an agent issues and rotates itself (Entra device and
    peer-to-peer certificates, MDM agent identities, Apple push and pairing
    certificates, Remote Desktop's self-signed certificate), and reference copies
    nobody owns: other people's email certificates and server certificates a
    user accepted.
``trust-store``
    Roots and intermediates the OS ships or caches, and UEFI Secure Boot
    certificates.

The signals, strongest first: where the certificate lives (store name and
location on Windows, keychain path on macOS), whether it is a CA, whether its
private key is present, and who issued it. Names are used only where nothing
else separates the cases, and only to recognise vendor-operated issuers.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

ACTIONABLE = "actionable"
SYSTEM_MANAGED = "system-managed"
TRUST_STORE = "trust-store"
CLASSES = (ACTIONABLE, SYSTEM_MANAGED, TRUST_STORE)

# Windows stores, by both the short name and the display name osquery reports.
_WINDOWS_TRUST_STORES = frozenset(
    {
        "root",
        "trusted root certification authorities",
        "authroot",
        "third-party root certification authorities",
        "ca",
        "intermediate certification authorities",
        "trustedpublisher",
        "trusted publishers",
        "disallowed",
        "untrusted certificates",
        "trustedpeople",
        "trusted people",
        "smartcardroot",
        "smart card trusted roots",
        "test roots",
        "testsignroot",
        "preview build roots",
        "flightroot",
        "esim certification authorities",
        "passpointtrustedroots",
        "clientauthissuer",
        "client authentication issuers",
        "trusteddevices",
        "trusted devices",
        "trustedappgallery",
    }
)

_WINDOWS_SYSTEM_STORES = frozenset(
    {
        "remote desktop",
        "windows live id token issuer",
        "aad token issuer",
        "homegroup machine certificates",
        "local nonremovable certificates",
        "msiehistoryjournal",
        "request",
        "requests",
        "certificate enrollment requests",
        "shielded vm local certificates",
        "addressbook",
        "other people",
    }
)

# Stores filled by Group Policy or published from Active Directory: anything here
# was put there by an administrator, so it is theirs to renew.
_WINDOWS_POLICY_LOCATIONS = frozenset(
    {
        "localmachinegrouppolicy",
        "localmachineenterprise",
        "currentusergrouppolicy",
        "usergrouppolicy",
    }
)

# Issuers whose certificates the OS or an agent requests and renews itself.
_SYSTEM_ISSUER_PREFIXES = (
    "ms-organization-p2p-access",
    "ms-organization-access",
    "microsoft intune mdm device ca",
    "microsoft intune mdm agent ca",
    "microsoft intune beta mdm",
    "microsoft device management device ca",
    "microsoft policy platform",
    "windows azure crp certificate generator",
    "apple iphone device ca",
    "apple iphone certification authority",
    "token signing public key",
)

_SYSTEM_SUBJECT_PREFIXES = (
    "com.apple.",
    "intunemdmagent-",
    "microsoft.office.",
    "ms-organization-",
)

# Development and loopback certificates are minted and replaced by the tooling
# that uses them.
_SYSTEM_SUBJECTS = frozenset({"localhost", "127.0.0.1", "::1"})

_MAC_TRUST_PREFIXES = ("/system/library/keychains/",)
_MAC_SYSTEM_KEYCHAINS = ("apsd.keychain", "filevaultmaster.keychain")

_GUID = re.compile(
    r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I
)
_HEX_ID = re.compile(r"^[0-9a-f]{24,}$", re.I)
# Last resort when a certificate carries no CA flag: a name that says CA.
_CA_NAME = re.compile(
    r"(\bCA\b|\bRoot\b|Certification Authority|Certificate Authority|\bIntermediate\b|Issuing CA)",
    re.I,
)
# Separators: "," (RFC 4514), "/" (OpenSSL one-line) and "+" (multi-valued RDN).
_RDN = re.compile(r"(?:^|[,/+]\s*)([A-Za-z.]+)\s*=\s*((?:\\.|[^,/+])+)")


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: Any) -> Optional[bool]:
    """A tri-state boolean: True, False, or None when the runner did not say."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes"):
            return True
        if v in ("0", "false", "no"):
            return False
    return None


def _rdns(dn: str) -> Dict[str, str]:
    """Parse ``CN=x, O=y`` and ``/CN=x/O=y`` into {attribute: first value}."""
    out: Dict[str, str] = {}
    for key, value in _RDN.findall(dn or ""):
        out.setdefault(key.strip().upper(), value.strip())
    return out


def issuer_name(cert: Dict[str, Any]) -> str:
    """The issuer's common name, or its organisation when it has none."""
    issuer = _text(cert.get("issuer"))
    parts = _rdns(issuer)
    for key in ("CN", "OU", "O"):
        if parts.get(key):
            return parts[key]
    # osquery on Windows reports the issuer as bare comma-joined values.
    if issuer and "=" not in issuer:
        return issuer.split(",")[-1].strip() or issuer
    return issuer


def _is_opaque(name: str) -> bool:
    return not name or bool(_GUID.match(name)) or bool(_HEX_ID.match(name))


def display_name(cert: Dict[str, Any]) -> str:
    """A name a person can read: never a bare GUID when anything better exists."""
    for key in ("commonName", "friendlyName"):
        name = _text(cert.get(key))
        if not _is_opaque(name):
            return name
    parts = _rdns(_text(cert.get("subject")))
    for key in ("CN", "EMAILADDRESS", "E", "OU", "O"):
        name = parts.get(key, "")
        if not _is_opaque(name):
            return name
    issuer = issuer_name(cert)
    if issuer:
        return f"Certificate from {issuer}"
    return _text(cert.get("commonName")) or "Unnamed certificate"


def _is_windows(cert: Dict[str, Any], platform: str) -> bool:
    p = (platform or "").lower()
    if p.startswith("win"):
        return True
    if p.startswith("mac") or p == "darwin":
        return False
    return not _text(cert.get("path")) and bool(_text(cert.get("storeName")))


def _system_issued(cert: Dict[str, Any]) -> bool:
    issuer = issuer_name(cert).lower()
    if issuer.startswith(_SYSTEM_ISSUER_PREFIXES):
        return True
    cn = _text(cert.get("commonName")).lower()
    return cn.startswith(_SYSTEM_SUBJECT_PREFIXES) or cn in _SYSTEM_SUBJECTS


def _is_ca(cert: Dict[str, Any]) -> Optional[bool]:
    for key in ("isCA", "isCa", "ca"):
        flag = _flag(cert.get(key))
        if flag is not None:
            return flag
    return None


def _classify_windows(cert: Dict[str, Any]) -> str:
    location = _text(cert.get("storeLocation")).lower()
    store = _text(cert.get("storeName")).lower()
    if location == "uefi":
        return TRUST_STORE
    if store in _WINDOWS_SYSTEM_STORES:
        return SYSTEM_MANAGED
    if store in _WINDOWS_TRUST_STORES:
        return ACTIONABLE if location in _WINDOWS_POLICY_LOCATIONS else TRUST_STORE
    if _system_issued(cert):
        return SYSTEM_MANAGED
    return ACTIONABLE


def _classify_mac(cert: Dict[str, Any]) -> str:
    path = _text(cert.get("path")).lower()
    if path.startswith(_MAC_TRUST_PREFIXES):
        return TRUST_STORE
    if path.endswith(_MAC_SYSTEM_KEYCHAINS):
        return SYSTEM_MANAGED
    if _system_issued(cert):
        return SYSTEM_MANAGED

    has_key = _flag(cert.get("hasPrivateKey"))
    is_ca = _is_ca(cert)
    self_signed = bool(_flag(cert.get("isSelfSigned")))
    if is_ca:
        return TRUST_STORE
    if self_signed and has_key is not True:
        # A self-signed certificate without its key is a trust anchor someone
        # accepted, not an identity anyone renews.
        return TRUST_STORE
    if (
        is_ca is None
        and has_key is None
        and _CA_NAME.search(_text(cert.get("commonName")))
    ):
        return TRUST_STORE

    in_user_keychain = (
        path.startswith("/users/") or _text(cert.get("storeLocation")).lower() == "user"
    )
    if in_user_keychain and has_key is False:
        # Mail keeps every correspondent's certificate and Safari or Wi-Fi keeps
        # server certificates a user accepted; without the key it is a copy.
        return SYSTEM_MANAGED
    return ACTIONABLE


def classify_certificate(cert: Dict[str, Any], platform: str = "") -> str:
    """``actionable``, ``system-managed`` or ``trust-store`` for one certificate."""
    if not isinstance(cert, dict):
        return SYSTEM_MANAGED
    if _is_windows(cert, platform):
        return _classify_windows(cert)
    return _classify_mac(cert)


# Expiry epochs outside 1970..9999 are not dates; dropping them keeps SQL's
# arithmetic on the epoch inside range.
_EPOCH_MIN = 0
_EPOCH_MAX = 253402300799


def _not_after_epoch(cert: Dict[str, Any]) -> Optional[int]:
    raw = cert.get("notAfter")
    try:
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            epoch = int(raw)
        else:
            text = _text(raw)
            if not text:
                return None
            if re.fullmatch(r"-?\d{1,15}(\.\d+)?", text):
                epoch = int(float(text))
            else:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                epoch = int(parsed.timestamp())
    except (ValueError, OverflowError, OSError):
        return None
    return epoch if _EPOCH_MIN <= epoch <= _EPOCH_MAX else None


def stamp_certificate(cert: Dict[str, Any], platform: str = "") -> Dict[str, Any]:
    """Return ``cert`` with ``class``, ``displayName``, ``issuerName`` and
    ``notAfterEpoch`` set. The epoch lets SQL work out expiry at query time
    rather than trusting ``daysUntilExpiry``, which is frozen at collection."""
    stamped = dict(cert)
    # Never keep a class or epoch the device sent: the API decides both.
    try:
        stamped["class"] = classify_certificate(cert, platform)
    except Exception:
        stamped["class"] = ACTIONABLE
    stamped["displayName"] = display_name(cert)
    stamped["issuerName"] = issuer_name(cert)
    epoch = _not_after_epoch(cert)
    if epoch is None:
        stamped.pop("notAfterEpoch", None)
    else:
        stamped["notAfterEpoch"] = epoch
    return stamped


def _stamp_safely(cert: Dict[str, Any], platform: str) -> Dict[str, Any]:
    """One odd certificate must not leave the rest, or itself, carrying
    whatever class the device claimed."""
    try:
        return stamp_certificate(cert, platform)
    except Exception:
        fallback = {k: v for k, v in cert.items() if k not in ("notAfterEpoch", "displayName", "issuerName")}
        fallback["class"] = ACTIONABLE
        return fallback


def stamp_certificates(security: Any, platform: str = "") -> Any:
    """Stamp every certificate in a security module payload. Anything that is
    not a dict with a ``certificates`` list is returned unchanged."""
    if not isinstance(security, dict) or not isinstance(
        security.get("certificates"), list
    ):
        return security
    out = dict(security)
    out["certificates"] = [_stamp_safely(c, platform) if isinstance(c, dict) else c for c in security["certificates"]]
    return out
