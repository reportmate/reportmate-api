"""Certificate search and per-device certificate counts, against real PostgreSQL.

Seeds two SAMPLE devices with certificates stamped the way ingest stamps them
(certificate_class.stamp_certificates) and checks that the search defaults to
actionable certificates, that every class stays reachable, that expiry comes
from notAfter rather than the frozen daysUntilExpiry, and that one certificate
listed in several Windows store views counts once.

Skipped without TEST_DATABASE_URL; CI provides one.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import pytest

from certificate_class import stamp_certificates

_TEST_DB = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB certificate tests"
)

SCHEMA = "certificates_test"
NOW = datetime.now(timezone.utc)
GUID = "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b"


def iso(**kw):
    return (NOW + timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%SZ")


WIN_CERTS = [
    # Entra peer-to-peer certificate: expiring today, rotates itself.
    {
        "commonName": GUID,
        "issuer": "MS-Organization-P2P-Access [2026]",
        "storeName": "Personal",
        "storeLocation": "LocalMachine",
        "thumbprint": "AA01",
        "notAfter": iso(hours=6),
    },
    # An expired OS root, in three store views.
    *[
        {
            "commonName": "SAMPLE Public Root",
            "storeName": "Trusted Root Certification Authorities",
            "storeLocation": loc,
            "thumbprint": "AA02",
            "notAfter": iso(days=-30),
        }
        for loc in ("LocalMachine", "Users", "CurrentService")
    ],
    # An enterprise root deployed by policy, expiring: seen in two views, the
    # policy view makes it actionable, and it counts once.
    {
        "commonName": "SAMPLE.CA",
        "storeName": "Trusted Root Certification Authorities",
        "storeLocation": "LocalMachine",
        "thumbprint": "AA03",
        "notAfter": iso(days=6),
    },
    {
        "commonName": "SAMPLE.CA",
        "storeName": "Trusted Root Certification Authorities",
        "storeLocation": "LocalMachineGroupPolicy",
        "thumbprint": "AA03",
        "notAfter": iso(days=6),
    },
    # A device identity from the organisation's CA, collected as valid for 3
    # days but expired since.
    {
        "commonName": "SAMPLE-PC01.sample.example",
        "issuer": "SAMPLE Issuing CA",
        "storeName": "Personal",
        "storeLocation": "LocalMachine",
        "thumbprint": "AA04",
        "notAfter": iso(days=-1),
        "daysUntilExpiry": 3,
        "isExpired": False,
        "isExpiringSoon": True,
        "status": "ExpiringSoon",
    },
]

MAC_CERTS = [
    {
        "commonName": "SAMPLE Root",
        "path": "/System/Library/Keychains/SystemRootCertificates.keychain",
        "isSelfSigned": 1,
        "notAfter": iso(days=-5),
    },
    {
        "commonName": "SAMPLE Wi-Fi",
        "issuer": "CN=SAMPLE Issuing CA",
        "path": "/Library/Keychains/System.keychain",
        "isCA": False,
        "hasPrivateKey": True,
        "notAfter": iso(days=20),
    },
    {
        "commonName": "Sample Person",
        "path": "/Users/sample/Library/Keychains/login.keychain-db",
        "isCA": False,
        "hasPrivateKey": False,
        "notAfter": iso(days=-100),
    },
]


def _connect(search_path=True):
    import pg8000

    pg8000.paramstyle = "pyformat"
    u = urlparse(_TEST_DB)
    conn = pg8000.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=u.username,
        password=u.password,
    )
    if search_path:
        conn.cursor().execute(f"SET search_path TO {SCHEMA}")
    return conn


@pytest.fixture(scope="module")
def db():
    conn = _connect(search_path=False)
    conn.autocommit = True
    cur = conn.cursor()
    for stmt in [
        f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE",
        f"CREATE SCHEMA {SCHEMA}",
        f"SET search_path TO {SCHEMA}",
        """CREATE TABLE devices (id TEXT PRIMARY KEY, device_id TEXT, serial_number TEXT UNIQUE, name TEXT,
               platform TEXT, archived BOOLEAN NOT NULL DEFAULT FALSE, last_seen TIMESTAMPTZ)""",
        "CREATE TABLE security (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB, collected_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())",
        "CREATE TABLE inventory (id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB)",
    ]:
        cur.execute(stmt)
    for serial, platform, certs in (
        ("SAMPLE1", "Windows", WIN_CERTS),
        ("SAMPLE2", "macOS", MAC_CERTS),
    ):
        cur.execute(
            "INSERT INTO devices (id, device_id, serial_number, name, platform, last_seen) VALUES (%s, %s, %s, %s, %s, NOW())",
            (serial, serial, serial, serial, platform),
        )
        data = stamp_certificates({"certificates": certs}, platform)
        cur.execute(
            "INSERT INTO security (device_id, data) VALUES (%s, %s::jsonb)",
            (serial, json.dumps(data)),
        )
        cur.execute(
            "INSERT INTO inventory (device_id, data) VALUES (%s, %s::jsonb)",
            (serial, json.dumps({"deviceName": f"{serial}-NAME"})),
        )
    conn.close()
    yield
    conn = _connect(search_path=False)
    conn.autocommit = True
    conn.cursor().execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    conn.close()


def _search(cert_class="actionable", status="all", search=""):
    from dependencies import load_sql

    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        load_sql("devices/security_certificates"),
        {
            "search": search,
            "status": status,
            "include_archived": False,
            "max_results": 100,
            "cert_class": cert_class,
        },
    )
    cols = [c[0] for c in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]
    conn.close()
    return rows


def _names(rows):
    return sorted(
        (r["serial_number"], r["display_name"], r["cert_status"]) for r in rows
    )


def test_search_defaults_to_actionable(db):
    assert _names(_search()) == [
        ("SAMPLE1", "SAMPLE-PC01.sample.example", "Expired"),
        ("SAMPLE1", "SAMPLE.CA", "ExpiringSoon"),
        ("SAMPLE2", "SAMPLE Wi-Fi", "ExpiringSoon"),
    ]


def test_hidden_classes_stay_reachable(db):
    system = _search("system-managed")
    assert _names(system) == [
        (
            "SAMPLE1",
            f"Certificate from MS-Organization-P2P-Access [2026]",
            "ExpiringSoon",
        ),
        ("SAMPLE2", "Sample Person", "Expired"),
    ]
    trust = _search("trust-store")
    # Three Windows views of one root collapse to one row; the policy-deployed
    # root's plain view is a trust-store view of an actionable certificate.
    assert _names(trust) == [
        ("SAMPLE1", "SAMPLE Public Root", "Expired"),
        ("SAMPLE1", "SAMPLE.CA", "ExpiringSoon"),
        ("SAMPLE2", "SAMPLE Root", "Expired"),
    ]
    assert len(_search("hidden")) == 5
    assert len(_search("all")) == 7


def test_status_is_live_not_frozen(db):
    expired = _search(status="expired")
    assert _names(expired) == [("SAMPLE1", "SAMPLE-PC01.sample.example", "Expired")]
    assert expired[0]["days_until_expiry"] < 0
    assert _names(_search(status="expiring")) == [
        ("SAMPLE1", "SAMPLE.CA", "ExpiringSoon"),
        ("SAMPLE2", "SAMPLE Wi-Fi", "ExpiringSoon"),
    ]


def test_search_matches_readable_name(db):
    assert _names(_search("system-managed", search="P2P-Access")) == [
        (
            "SAMPLE1",
            "Certificate from MS-Organization-P2P-Access [2026]",
            "ExpiringSoon",
        ),
    ]


def test_bulk_security_counts_actionable_only(db):
    from dependencies import load_sql

    conn = _connect()
    cur = conn.cursor()
    cur.execute(load_sql("devices/bulk_security"), {"include_archived": False})
    cols = [c[0] for c in cur.description]
    rows = {r[0]: dict(zip(cols, r)) for r in cur.fetchall()}
    conn.close()

    win = rows["SAMPLE1"]
    assert (
        win["certificate_count"] == 4
    )  # four distinct certificates across seven views
    assert (
        win["actionable_cert_count"],
        win["system_managed_cert_count"],
        win["trust_store_cert_count"],
    ) == (2, 1, 1)
    assert (win["expired_cert_count"], win["expiring_soon_cert_count"]) == (1, 1)
    assert win["user_expired_cert_count"] == 1
    assert win["os_root_expired_cert_count"] == 1

    mac = rows["SAMPLE2"]
    assert (
        mac["actionable_cert_count"],
        mac["system_managed_cert_count"],
        mac["trust_store_cert_count"],
    ) == (1, 1, 1)
    assert (mac["expired_cert_count"], mac["expiring_soon_cert_count"]) == (0, 1)
    assert mac["system_managed_expired_cert_count"] == 1
