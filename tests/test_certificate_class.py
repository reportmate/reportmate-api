"""Which certificates an admin can act on (certificate_class.py).

Fixtures are SAMPLE-style shapes of what the runners report: Windows rows come
from osquery's certificates table (display store names, bare comma-joined
issuers), macOS rows carry the keychain path.
"""

import pytest

from certificate_class import (
    ACTIONABLE,
    SYSTEM_MANAGED,
    TRUST_STORE,
    classify_certificate,
    display_name,
    issuer_name,
    stamp_certificate,
    stamp_certificates,
)

GUID = "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"


def win(store, location="LocalMachine", **kw):
    return {"storeName": store, "storeLocation": location, **kw}


def mac(path, **kw):
    return {
        "path": path,
        "storeLocation": "User" if path.startswith("/Users/") else "System",
        **kw,
    }


@pytest.mark.parametrize(
    "cert, expected",
    [
        # Entra peer-to-peer certificates rotate daily on their own.
        (
            win(
                "Personal", commonName=GUID, issuer="MS-Organization-P2P-Access [2026]"
            ),
            SYSTEM_MANAGED,
        ),
        (
            win(
                "Personal",
                "Users",
                commonName="sample@example.org",
                issuer="MS-Organization-P2P-Access [2026]",
            ),
            SYSTEM_MANAGED,
        ),
        (
            win("Personal", commonName=GUID, issuer="Microsoft Intune MDM Device CA"),
            SYSTEM_MANAGED,
        ),
        (
            win(
                "Personal",
                "Users",
                commonName=GUID,
                issuer="US, Apple Inc., Apple iPhone, Apple iPhone Device CA",
            ),
            SYSTEM_MANAGED,
        ),
        (
            win("Remote Desktop", commonName="SAMPLE-PC01", isSelfSigned=True),
            SYSTEM_MANAGED,
        ),
        (
            win("Windows Live ID Token Issuer", commonName="Token Signing Public Key"),
            SYSTEM_MANAGED,
        ),
        (
            win("Personal", "Users", commonName="localhost", isSelfSigned=True),
            SYSTEM_MANAGED,
        ),
        # Trust stores, in every logical view, and Secure Boot.
        (
            win(
                "Trusted Root Certification Authorities",
                commonName="SAMPLE Public Root",
            ),
            TRUST_STORE,
        ),
        (
            win(
                "Intermediate Certification Authorities",
                "Users",
                commonName="SAMPLE Issuing CA 01",
            ),
            TRUST_STORE,
        ),
        (
            win("Third-Party Root Certification Authorities", commonName="SAMPLE Root"),
            TRUST_STORE,
        ),
        (
            win("Trusted Publishers", "CurrentService", commonName="SAMPLE Publisher"),
            TRUST_STORE,
        ),
        (win("db", "UEFI", commonName="SAMPLE UEFI CA 2011"), TRUST_STORE),
        # A root an administrator deployed by policy is theirs to renew.
        (
            win(
                "Trusted Root Certification Authorities",
                "LocalMachineGroupPolicy",
                commonName="SAMPLE.CA",
            ),
            ACTIONABLE,
        ),
        (
            win(
                "Trusted Root Certification Authorities",
                "LocalMachineEnterprise",
                commonName="SAMPLE.CA",
            ),
            ACTIONABLE,
        ),
        # Identities from the organisation's PKI or a profile.
        (
            win(
                "Personal",
                commonName="SAMPLE-PC01.sample.example",
                issuer="SAMPLE Issuing CA",
            ),
            ACTIONABLE,
        ),
        (
            win(
                "Personal",
                "Users",
                commonName="SAMPLE Enterprise Certificate",
                isSelfSigned=True,
            ),
            ACTIONABLE,
        ),
        (
            win(
                "My",
                "CurrentUser",
                commonName="sample.user",
                issuer="CN=SAMPLE Issuing CA, DC=sample",
            ),
            ACTIONABLE,
        ),
    ],
)
def test_windows(cert, expected):
    assert classify_certificate(cert, "Windows") == expected


@pytest.mark.parametrize(
    "cert, expected",
    [
        (
            mac(
                "/System/Library/Keychains/SystemRootCertificates.keychain",
                commonName="SAMPLE Root",
                isSelfSigned=1,
            ),
            TRUST_STORE,
        ),
        (
            mac("/System/Library/Keychains/X509Anchors", commonName="SAMPLE Old Root"),
            TRUST_STORE,
        ),
        (
            mac(
                "/Library/Keychains/apsd.keychain",
                commonName=GUID,
                issuer="Apple iPhone Device CA",
            ),
            SYSTEM_MANAGED,
        ),
        (
            mac(
                "/Library/Keychains/System.keychain",
                commonName="com.apple.kerberos.kdc",
                issuer="com.apple.kerberos.kdc",
            ),
            SYSTEM_MANAGED,
        ),
        (
            mac(
                "/Library/Keychains/System.keychain",
                commonName="IntuneMDMAgent-" + GUID,
                issuer="Microsoft Intune MDM Agent CA",
            ),
            SYSTEM_MANAGED,
        ),
        (
            mac(
                "/Library/Keychains/System.keychain",
                commonName=GUID,
                issuer="Microsoft Intune MDM Device CA",
            ),
            SYSTEM_MANAGED,
        ),
        (
            mac(
                "/Users/sample/Library/Keychains/login.keychain-db",
                commonName="Microsoft.Office.Excel.ProtectedDataServices",
            ),
            SYSTEM_MANAGED,
        ),
        # CA certificates in any keychain are trust anchors.
        (
            mac(
                "/Library/Keychains/System.keychain",
                commonName="SAMPLE Issuing",
                isCA=True,
            ),
            TRUST_STORE,
        ),
        (
            mac(
                "/Users/sample/Library/Keychains/login.keychain-db",
                commonName="SAMPLE Intermediate CA G2",
            ),
            TRUST_STORE,
        ),
        (
            mac(
                "/Users/sample/Library/Keychains/login.keychain-db",
                commonName="sample.example",
                isSelfSigned=1,
            ),
            TRUST_STORE,
        ),
        # A correspondent's email certificate or an accepted server certificate:
        # no private key, nothing to renew.
        (
            mac(
                "/Users/sample/Library/Keychains/login.keychain-db",
                commonName="Sample Person",
                hasPrivateKey=False,
                isCA=False,
            ),
            SYSTEM_MANAGED,
        ),
        (
            mac(
                "/Users/sample/Library/Keychains/login.keychain-db",
                commonName="radius.sample.example",
                hasPrivateKey=False,
                isCA=False,
            ),
            SYSTEM_MANAGED,
        ),
        # Identities deployed by a profile.
        (
            mac(
                "/Library/Keychains/System.keychain",
                commonName="SAMPLE-MAC01",
                issuer="CN=SAMPLE Issuing CA",
                isCA=False,
            ),
            ACTIONABLE,
        ),
        (
            mac(
                "/Users/sample/Library/Keychains/login.keychain-db",
                commonName="sample.user",
                hasPrivateKey=True,
                isCA=False,
            ),
            ACTIONABLE,
        ),
        # Older runners send no key or CA flag: keep it visible rather than hide it.
        (
            mac(
                "/Users/sample/Library/Keychains/login.keychain-db",
                commonName="Sample Person",
            ),
            ACTIONABLE,
        ),
    ],
)
def test_macos(cert, expected):
    assert classify_certificate(cert, "macOS") == expected


def test_platform_inferred_from_shape():
    assert (
        classify_certificate(win("Root", commonName="SAMPLE Root"), "") == TRUST_STORE
    )
    assert (
        classify_certificate(
            mac("/System/Library/Keychains/SystemRootCertificates.keychain"), ""
        )
        == TRUST_STORE
    )


def test_issuer_name_handles_every_issuer_shape():
    assert (
        issuer_name({"issuer": "CN=SAMPLE Issuing CA, O=Sample, C=CA"})
        == "SAMPLE Issuing CA"
    )
    assert issuer_name({"issuer": "/C=CA/O=Sample/OU=SAMPLE Unit"}) == "SAMPLE Unit"
    assert issuer_name({"issuer": "CA, SAMPLE, SAMPLE.CA"}) == "SAMPLE.CA"
    assert (
        issuer_name({"issuer": "MS-Organization-P2P-Access [2026]"})
        == "MS-Organization-P2P-Access [2026]"
    )


def test_display_name_never_a_bare_guid_when_something_better_exists():
    assert display_name({"commonName": "SAMPLE Wi-Fi"}) == "SAMPLE Wi-Fi"
    assert (
        display_name({"commonName": GUID, "friendlyName": "SAMPLE Device"})
        == "SAMPLE Device"
    )
    assert (
        display_name({"commonName": GUID, "subject": f"CN={GUID}, O=SAMPLE Org"})
        == "SAMPLE Org"
    )
    assert display_name(
        {"commonName": GUID, "issuer": "MS-Organization-P2P-Access [2026]"}
    ) == ("Certificate from MS-Organization-P2P-Access [2026]")


def test_stamp_adds_class_names_and_epoch():
    stamped = stamp_certificate(
        win(
            "Personal",
            commonName=GUID,
            issuer="MS-Organization-P2P-Access [2026]",
            notAfter="2026-01-02T00:00:00Z",
        ),
        "Windows",
    )
    assert stamped["class"] == SYSTEM_MANAGED
    assert stamped["issuerName"] == "MS-Organization-P2P-Access [2026]"
    assert stamped["notAfterEpoch"] == 1767312000
    assert (
        stamp_certificate({"notAfter": "2026-01-02T00:00:00"}, "Windows")[
            "notAfterEpoch"
        ]
        == 1767312000
    )
    assert "notAfterEpoch" not in stamp_certificate(
        {"notAfter": "not a date"}, "Windows"
    )


def test_stamp_certificates_leaves_odd_payloads_alone():
    assert stamp_certificates(None) is None
    assert stamp_certificates({"certificates": {"not": "a list"}}) == {
        "certificates": {"not": "a list"}
    }
    out = stamp_certificates(
        {"certificates": [win("Root"), "junk"], "other": 1}, "Windows"
    )
    assert out["certificates"][0]["class"] == TRUST_STORE
    assert out["certificates"][1] == "junk"
    assert out["other"] == 1


def test_stamping_is_idempotent():
    once = stamp_certificates(
        {"certificates": [win("Personal", commonName="SAMPLE")]}, "Windows"
    )
    assert stamp_certificates(once, "Windows") == once


def test_device_supplied_class_and_epoch_never_survive():
    stamped = stamp_certificates(
        {"certificates": [win("Root", commonName="SAMPLE Root", **{"class": "actionable", "notAfterEpoch": 10**30})]},
        "Windows",
    )["certificates"][0]
    assert stamped["class"] == TRUST_STORE
    assert "notAfterEpoch" not in stamped


@pytest.mark.parametrize("not_after", ["1e400", "9" * 40, 10**30, float("inf"), "99999-01-01", -5])
def test_out_of_range_expiry_is_dropped(not_after):
    assert "notAfterEpoch" not in stamp_certificate({"notAfter": not_after}, "Windows")


def test_multi_valued_issuer_names_parse():
    issuer = "/DC=net+DC=windows+CN=MS-Organization-Access+OU=" + GUID
    assert issuer_name({"issuer": issuer}) == "MS-Organization-Access"
    cert = mac(
        "/Users/sample/Library/Keychains/login.keychain-db",
        commonName=GUID,
        issuer=issuer,
        hasPrivateKey=True,
        isCA=False,
    )
    assert classify_certificate(cert, "macOS") == SYSTEM_MANAGED


def test_packaged_app_authorities_are_a_trust_store():
    cert = win("Trusted Packaged App Installation Authorities", commonName="SAMPLE Packaging Root")
    assert classify_certificate(cert, "Windows") == TRUST_STORE
