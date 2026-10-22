"""The dashboard insight card queries, executed against real PostgreSQL.

Every card is jsonb aggregation, and that only fails against a server: a
cast that throws on one odd value, a FILTER that drops NULLs, a LATERAL over a
non-array. These tests build the module tables in their own schema, seed a
small SAMPLE fleet whose answers are worked out by hand below, and check each
card's numbers and deep links.

Skipped without TEST_DATABASE_URL; CI provides one.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import pytest

_TEST_DB = os.getenv("TEST_DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _TEST_DB, reason="TEST_DATABASE_URL not set; skipping live-DB insights tests"
)

SCHEMA = "insights_test"
NOW = datetime.now(timezone.utc)

MODULE_TABLES = (
    "system",
    "security",
    "management",
    "hardware",
    "installs",
    "inventory",
    "identity",
    "network",
    "applications",
)

DDL = [
    f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE",
    f"CREATE SCHEMA {SCHEMA}",
    """CREATE TABLE devices (
           id TEXT PRIMARY KEY, device_id TEXT, serial_number TEXT UNIQUE, name TEXT,
           os TEXT, os_name TEXT, os_version TEXT, platform TEXT,
           archived BOOLEAN NOT NULL DEFAULT FALSE, last_seen TIMESTAMPTZ,
           created_at TIMESTAMPTZ DEFAULT NOW())""",
    *[
        f"""CREATE TABLE {t} (
               id SERIAL PRIMARY KEY, device_id TEXT UNIQUE, data JSONB,
               collected_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW())"""
        for t in MODULE_TABLES
    ],
    "ALTER TABLE installs ADD COLUMN cimian_errors INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE installs ADD COLUMN cimian_warnings INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE installs ADD COLUMN munki_errors INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE installs ADD COLUMN munki_warnings INTEGER NOT NULL DEFAULT 0",
    """CREATE TABLE usage_history (
           id SERIAL PRIMARY KEY, device_id TEXT NOT NULL, date DATE NOT NULL,
           app_name TEXT NOT NULL, launches INTEGER NOT NULL DEFAULT 0,
           total_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
           active_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
           users JSONB DEFAULT '[]'::jsonb)""",
    """CREATE TABLE ingest_failures (
           id BIGSERIAL PRIMARY KEY, occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
           failure_type VARCHAR(20) NOT NULL, reason VARCHAR(50) NOT NULL, detail TEXT,
           status_code INTEGER, endpoint VARCHAR(200), client_ip VARCHAR(64),
           user_agent VARCHAR(400), serial_number VARCHAR(255), device_uuid VARCHAR(255),
           device_name VARCHAR(255), platform VARCHAR(32), client_version VARCHAR(64))""",
    "CREATE TABLE device_ingest_state (device_id TEXT PRIMARY KEY, last_accepted_at TIMESTAMPTZ)",
    """CREATE TABLE device_inventory_state (
           serial_number TEXT PRIMARY KEY, state TEXT NOT NULL, storage_location TEXT,
           lease_number TEXT, asset_tag TEXT, updated_at TIMESTAMPTZ DEFAULT NOW())""",
]


def ago(**kw):
    return NOW - timedelta(**kw)


def iso(dt):
    return dt.isoformat()


def mac_os(version):
    return {
        "operatingSystem": {"name": "macOS", "version": version, "platform": "Darwin"}
    }


def win_os(name, build, ubr):
    return {
        "operatingSystem": {
            "name": name,
            "edition": "Enterprise",
            "build": build,
            "featureUpdate": ubr,
        }
    }


# serial: (platform, last_seen, archived)
DEVICES = {
    "SAMPLE1": ("macOS", NOW, False),
    "SAMPLE2": ("macOS", NOW, False),
    "SAMPLE3": ("macOS", NOW, False),
    "SAMPLE4": ("macOS", NOW, False),
    "SAMPLE5": ("macOS", NOW, False),
    "SAMPLE6": ("macOS", NOW, False),
    "SAMPLE7": ("macOS", None, False),
    "SAMPLE8": ("Windows", NOW, False),
    "SAMPLE9": ("Windows", ago(days=3), False),
    "SAMPLE10": ("Windows", ago(days=10), False),
    "SAMPLE11": ("macOS", NOW, True),
    "SAMPLE12": ("macOS", NOW, False),
    "TEST-SAMPLE13": ("macOS", NOW, False),
}

SYSTEM = {
    "SAMPLE1": {
        **mac_os("26.3.1"),
        "uptime": 3000000,
        "pendingAppleUpdates": [{"name": "SAMPLE update", "deferred": True}],
    },
    "SAMPLE2": {
        **mac_os("26.3.1"),
        "uptime": "15.02:03:04",
        "pending_apple_updates": [],
    },
    "SAMPLE3": {**mac_os("26.3.1"), "uptimeString": "3d 4h"},
    "SAMPLE4": {**mac_os("26.3.1"), "uptime": 90000},
    "SAMPLE5": {**mac_os("26.3.1"), "uptime": 90000},
    "SAMPLE6": {**mac_os("26.2"), "uptime": 90000},
    "SAMPLE7": {**mac_os("13.6.1"), "uptime": 90000},
    "SAMPLE8": {
        **win_os("Windows 11", "26100", "4000"),
        "uptime": 100,
        "pendingWindowsUpdatesCount": 3,
    },
    "SAMPLE9": {
        **win_os("Windows 10", "19045", "5000"),
        "uptime": "abc",
        "pendingWindowsUpdates": [{}, {}],
    },
    "SAMPLE10": {**win_os("Windows 11", "26100", "3000"), "uptime": 90000},
    "SAMPLE11": {**mac_os("26.3.1"), "uptime": 3000000},
    "SAMPLE12": {**mac_os("26.3.1"), "uptime": 3000000},
    "TEST-SAMPLE13": {**mac_os("26.3.1"), "uptime": 3000000},
}

SECURITY = {
    "SAMPLE1": {
        "fileVault": {"enabled": True},
        "firewall": {"isEnabled": True},
        "systemIntegrityProtection": {"enabled": True},
        "certificates": [
            {
                "commonName": "SAMPLE Wi-Fi",
                "isExpiringSoon": True,
                "isExpired": False,
                "daysUntilExpiry": 12,
            },
            {
                "commonName": "SAMPLE Later",
                "isExpiringSoon": True,
                "isExpired": False,
                "daysUntilExpiry": 45,
            },
        ],
        "certificateSummary": {"userExpiredCount": 1},
        "securityCves": [
            {"status": "Unpatched", "severity": "Critical", "activelyExploited": True}
        ],
    },
    "SAMPLE2": {
        "fileVault": {"enabled": False},
        "firewall": {"globalState": "off"},
        "systemIntegrityProtection": {"enabled": "false"},
        "detections": [{"category": "ASR Rule", "eventId": 1121}],
        "certificates": [
            {
                "commonName": "SAMPLE Wi-Fi",
                "isExpiringSoon": True,
                "isExpired": False,
                "daysUntilExpiry": 5,
            },
            {
                "commonName": "SAMPLE Old",
                "isExpiringSoon": True,
                "isExpired": True,
                "daysUntilExpiry": -3,
            },
        ],
    },
    "SAMPLE8": {
        "encryption": {
            "bitLocker": {"isEnabled": True},
            "encryptedVolumes": [{"encryptionMethod": "None"}],
        },
        "firewall": {"enabled": True},
        "antivirus": {"name": "Defender", "isEnabled": False},
        "secureBoot": {"isEnabled": False},
        "detections": [{"category": "Trojan", "eventId": 1116}],
        "certificates": {"not": "an array"},
    },
    "SAMPLE9": {
        "encryption": {
            "bitLocker": {"isEnabled": "true"},
            "encryptedVolumes": [{"encryptionMethod": "AES-256"}],
        },
        "firewall": {"isEnabled": "true"},
        "antivirus": {"name": "Defender", "isEnabled": True},
        "secureBoot": {"isEnabled": True},
        "securityCves": "not an array",
    },
    "SAMPLE11": {"fileVault": {"enabled": False}},
}

MANAGEMENT = {
    "SAMPLE1": {"mdmEnrollment": {"enrolled": "true"}},
    "SAMPLE2": {"mdmEnrollment": {"isEnrolled": False}},
    "SAMPLE8": {"mdm_enrollment": {"is_enrolled": True}},
    "SAMPLE9": {"mdmEnrollment": {}},
    "SAMPLE11": {"mdmEnrollment": {"isEnrolled": False}},
}

HARDWARE = {
    "SAMPLE1": {
        "memory": {"totalFormatted": "8 GB"},
        "processor": "Apple M1",
        "storage": [{"capacity": 1000, "freeSpace": 50, "isInternal": True}],
    },
    "SAMPLE2": {
        "memory": 17179869184,
        "processor": {"name": "Intel Core i5"},
        "storage": [
            {"size": 1000, "freeSpace": 500},
            {"capacity": 1000, "freeSpace": 1, "isInternal": False},
        ],
    },
    "SAMPLE8": {
        "memory": {"physicalMemory": 8589934592},
        "processor": "Intel Xeon",
        "storage": "unknown",
    },
}

INSTALLS = {
    "SAMPLE1": (
        {
            "munki": {
                "endTime": iso(ago(days=10)),
                "items": [
                    {
                        "name": "Firefox",
                        "reportmateStatus": "error",
                        "installedVersion": "1",
                        "version": "2",
                    },
                    {
                        "name": "Chrome",
                        "status": "installed",
                        "installedVersion": "3",
                        "version": "3",
                    },
                ],
            }
        },
        {"munki_errors": 1},
    ),
    "SAMPLE2": (
        {
            "munki": {
                "endTime": iso(ago(days=1)),
                "items": [
                    {"name": "Firefox", "currentStatus": "Error"},
                    {
                        "name": "Zoom",
                        "reportmateStatus": "warning",
                        "installedVersion": "5",
                        "version": "6",
                    },
                ],
            }
        },
        {"munki_warnings": 1},
    ),
    "SAMPLE8": (
        {
            "cimian": {
                "sessions": [
                    {"end_time": iso(ago(days=20))},
                    {"start_time": iso(ago(days=30))},
                ],
                "items": [
                    {
                        "itemName": "Firefox",
                        "reportmateStatus": "error",
                        "installedVersion": "1",
                        "latestVersion": "2",
                    },
                    {
                        "itemName": "7zip",
                        "reportmateStatus": "installed",
                        "installedVersion": "1",
                        "latestVersion": "1",
                    },
                ],
            }
        },
        {"cimian_errors": 1},
    ),
}

IDENTITY = {
    "SAMPLE1": {
        "users": [{"isAdmin": True}, {"isAdmin": True}, {"isAdmin": False}],
        "directoryServices": {},
    },
    "SAMPLE8": {
        "users": [{"isAdmin": True}] * 4,
        "directoryServices": {
            "activeDirectory": {"bound": True},
            "azureAd": {"isAadJoined": True},
        },
    },
    "SAMPLE9": {
        "userAccounts": [{"isAdmin": True}],
        "directory_services": {"azure_ad": {"joined": True}},
    },
}

NETWORK = {
    "SAMPLE1": {
        "activeConnection": {"wifiSignalStrength": 20, "interfaceName": "en0"},
        "networkQuality": {"rating": "Low"},
    },
    "SAMPLE2": {
        "activeConnection": {"interfaceName": "utun3"},
        "networkQuality": {"dl_rating": "High"},
    },
    "SAMPLE8": {
        "active_connection": {"wifi_signal_strength": 80, "is_vpn_active": False},
        "vpnConnections": [{"name": "SAMPLE VPN", "status": "Connected"}],
    },
}

APPLICATIONS = {
    "SAMPLE1": {
        "installedApplications": [{"name": "Firefox.app"}, {"name": "Slack.app"}]
    },
    "SAMPLE2": {"installedApplications": [{"name": "Firefox"}, {"name": "Slack"}]},
    "SAMPLE8": {"installedApplications": [{"name": "Firefox"}]},
}

USAGE = [
    ("SAMPLE1", "Firefox", 7200, 3600),
    ("SAMPLE2", "Firefox", 3600, 0),
    ("SAMPLE1", "Slack", 36000, 1800),
]


def _connect(search_path=True):
    import pg8000

    u = urlparse(_TEST_DB)
    conn = pg8000.connect(
        host=u.hostname,
        port=u.port or 5432,
        database=u.path.lstrip("/"),
        user=u.username,
        password=u.password,
    )
    if search_path:
        conn.autocommit = True
        conn.cursor().execute(f"SET search_path TO {SCHEMA}")
        conn.autocommit = False
    return conn


@pytest.fixture(scope="module")
def seeded():
    conn = _connect(search_path=False)
    conn.autocommit = True
    cur = conn.cursor()
    for stmt in DDL[:2]:
        cur.execute(stmt)
    cur.execute(f"SET search_path TO {SCHEMA}")
    for stmt in DDL[2:]:
        cur.execute(stmt)

    for serial, (platform, last_seen, archived) in DEVICES.items():
        cur.execute(
            "INSERT INTO devices (id, device_id, serial_number, name, platform, archived, last_seen) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                serial,
                f"uuid-{serial}",
                serial,
                f"{serial}-name",
                platform,
                archived,
                last_seen,
            ),
        )
    for table, rows in (
        ("system", SYSTEM),
        ("security", SECURITY),
        ("management", MANAGEMENT),
        ("hardware", HARDWARE),
        ("identity", IDENTITY),
        ("network", NETWORK),
        ("applications", APPLICATIONS),
    ):
        for serial, data in rows.items():
            cur.execute(
                f"INSERT INTO {table} (device_id, data) VALUES (%s, %s::jsonb)",
                (serial, json.dumps(data)),
            )
    for serial, (data, counters) in INSTALLS.items():
        cols = ", ".join(["device_id", "data", *counters])
        marks = ", ".join(["%s", "%s::jsonb", *["%s"] * len(counters)])
        cur.execute(
            f"INSERT INTO installs ({cols}) VALUES ({marks})",
            (serial, json.dumps(data), *counters.values()),
        )
    cur.execute(
        "INSERT INTO device_inventory_state (serial_number, state) VALUES ('SAMPLE12', 'storage')"
    )
    for serial, app, total, active in USAGE:
        cur.execute(
            "INSERT INTO usage_history (device_id, date, app_name, total_seconds, active_seconds) VALUES (%s, %s, %s, %s, %s)",
            (serial, (NOW - timedelta(days=2)).date(), app, total, active),
        )
    cur.execute(
        "INSERT INTO usage_history (device_id, date, app_name, total_seconds, active_seconds) VALUES (%s, %s, %s, %s, %s)",
        ("SAMPLE8", (NOW - timedelta(days=60)).date(), "Firefox", 99999, 99999),
    )
    for occurred, reason, status, serial in (
        (ago(hours=2), "invalid_passphrase", 401, "SAMPLE1"),
        (ago(hours=3), "invalid_passphrase", 401, "SAMPLE99"),
        (ago(hours=4), "upload_aborted", 400, "SAMPLE2"),
        (ago(hours=5), "nul_in_payload", 200, "SAMPLE8"),
        (ago(hours=30), "invalid_passphrase", 401, "SAMPLE1"),
    ):
        cur.execute(
            "INSERT INTO ingest_failures (occurred_at, failure_type, reason, status_code, serial_number) "
            "VALUES (%s, 'auth', %s, %s, %s)",
            (occurred, reason, status, serial),
        )
    cur.execute(
        "INSERT INTO device_ingest_state (device_id, last_accepted_at) VALUES ('SAMPLE2', %s)",
        (NOW,),
    )
    conn.close()

    yield

    conn = _connect(search_path=False)
    conn.autocommit = True
    conn.cursor().execute(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
    conn.close()


@pytest.fixture
def insights(seeded, monkeypatch):
    import dashboard_insights

    monkeypatch.setattr(dashboard_insights, "get_db_connection", lambda: _connect())
    monkeypatch.setattr(dashboard_insights, "MIN_INSTALLS_FOR_LEAST_USED", 2)
    return dashboard_insights


def test_every_card_computes(insights):
    result = insights.compute_insights("all", False)
    assert set(result["cards"]) == set(insights.CARD_KEYS)
    errors = {k: v["error"] for k, v in result["cards"].items() if "error" in v}
    assert errors == {}


def test_reboot_debt(insights):
    card = insights.compute_insights("all", False)["cards"]["rebootDebt"]
    assert card["devices"] == 10
    buckets = {b["key"]: b["count"] for b in card["uptimeBuckets"]}
    assert buckets == {"lt1d": 1, "1-3d": 5, "3-7d": 1, "1-2w": 0, "2-4w": 1, "30d+": 1}
    assert card["pendingUpdates"]["count"] == 3
    assert card["deferredUpdates"]["count"] == 1
    assert card["uptime30dPlus"]["link"] == {
        "path": "/system",
        "params": {"uptime": "30d+"},
    }


def test_protection_gaps(insights):
    card = insights.compute_insights("all", False)["cards"]["protectionGaps"]
    gaps = {g["key"]: (g["count"], g["total"]) for g in card["gaps"]}
    assert gaps == {
        "encryption": (2, 4),
        "firewall": (1, 4),
        "antivirus": (1, 2),
        "sip": (1, 2),
        "secureBoot": (1, 2),
    }
    assert card["gaps"][0]["key"] == "encryption"
    assert card["withThreats"]["count"] == 1
    assert card["criticalCves"]["count"] == 1


def test_unmanaged_devices(insights):
    card = insights.compute_insights("all", False)["cards"]["unmanagedDevices"]
    assert card["devices"] == 4
    assert card["unmanaged"]["count"] == 2
    assert card["unmanaged"]["pct"] == 50
    assert card["unmanaged"]["link"] == {
        "path": "/management",
        "params": {"enrolled": "0"},
    }
    assert {b["key"]: b["count"] for b in card["lastSeen"]} == {
        "24h": 1,
        "7d": 1,
        "silent": 0,
    }
    assert [d["serialNumber"] for d in card["recent"]] == ["SAMPLE2", "SAMPLE9"]
    assert card["recent"][0]["link"] == {"path": "/device/SAMPLE2", "params": {}}


def test_unmanaged_devices_platform_filter(insights):
    card = insights.compute_insights("Windows", False)["cards"]["unmanagedDevices"]
    assert (card["devices"], card["unmanaged"]["count"]) == (2, 1)


def test_hardware_at_risk(insights):
    card = insights.compute_insights("all", False)["cards"]["hardwareAtRisk"]
    assert card["devices"] == 3
    assert card["lowStorage"]["count"] == 1
    assert card["lowMemory"]["count"] == 2
    assert (card["intelMacs"]["count"], card["intelMacs"]["macs"]) == (1, 2)


def test_install_health(insights):
    card = insights.compute_insights("all", False)["cards"]["installHealth"]
    assert card["withErrors"]["count"] == 2
    assert card["withWarnings"]["count"] == 1
    assert card["topFailing"] == [
        {
            "name": "Firefox",
            "devices": 3,
            "link": {
                "path": "/installs",
                "params": {"item": "Firefox", "filter": "errors"},
            },
        }
    ]
    assert card["silentAgents"]["count"] == 2


def test_checkin_gaps(insights):
    card = insights.compute_insights("all", False)["cards"]["checkinGaps"]
    assert (
        card["rejected"]["count"],
        card["retried"]["count"],
        card["accepted"]["count"],
    ) == (2, 1, 1)
    assert [(r["reason"], r["count"], r["devices"]) for r in card["reasons"]] == [
        ("invalid_passphrase", 2, 2)
    ]
    assert card["reasons"][0]["link"]["params"] == {
        "hours": "24",
        "reason": "invalid_passphrase",
    }
    assert (card["stale"]["count"], card["missing"]["count"]) == (1, 2)


def test_os_currency(insights):
    card = insights.compute_insights("all", False)["cards"]["osCurrency"]
    assert card["rated"] == 10
    assert card["behind"]["count"] == 2
    assert card["unsupportedMac"]["count"] == 1
    assert card["windows10"]["count"] == 1
    assert [(v["version"], v["devices"]) for v in card["lagging"]] == [
        ("11.26100", 1),
        ("26.2", 1),
    ]

    mac = insights.compute_insights("macOS", False)["cards"]["osCurrency"]
    assert (mac["rated"], mac["behind"]["count"], mac["windows10"]["count"]) == (
        7,
        1,
        0,
    )


def test_software_risk(insights):
    card = insights.compute_insights("all", False)["cards"]["softwareRisk"]
    assert card["criticalCves"]["count"] == 1
    assert card["exploitedCves"]["count"] == 1
    assert [(i["name"], i["devices"]) for i in card["itemsBehind"]] == [
        ("Firefox", 2),
        ("Zoom", 1),
    ]


def test_expiring_certificates(insights):
    card = insights.compute_insights("all", False)["cards"]["expiringCertificates"]
    assert (card["expiring"]["certificates"], card["expiring"]["devices"]) == (2, 2)
    assert card["expiredUser"]["devices"] == 1
    assert card["soonest"] == [
        {
            "commonName": "SAMPLE Wi-Fi",
            "daysUntilExpiry": 5,
            "devices": 2,
            "link": {
                "path": "/security",
                "params": {"certSearch": "SAMPLE Wi-Fi", "certStatus": "expiring"},
            },
        }
    ]


def test_local_admin_exposure(insights):
    card = insights.compute_insights("all", False)["cards"]["localAdminExposure"]
    assert card["extraAdmins"]["count"] == 2
    assert {b["key"]: b["count"] for b in card["byAdminCount"]} == {
        "2": 1,
        "3": 0,
        "4+": 1,
    }
    assert {j["key"]: j["count"] for j in card["join"]} == {
        "entra": 1,
        "domain": 0,
        "hybrid": 1,
        "workgroup": 1,
    }
    assert [(d["serialNumber"], d["admins"]) for d in card["topDevices"]] == [
        ("SAMPLE8", 4),
        ("SAMPLE1", 2),
    ]


def test_unused_software(insights):
    card = insights.compute_insights("all", False)["cards"]["unusedSoftware"]
    firefox, slack = insights.fold_name("Firefox"), insights.fold_name("Slack")
    assert [
        (a["name"], a["activeDevices"], a["installedDevices"])
        for a in card["leastUsed"]
    ] == [
        (firefox, 1, 3),
        (slack, 1, 2),
    ]
    assert [(a["name"], a["totalHours"]) for a in card["mostUsed"]] == [
        (slack, 10.0),
        (firefox, 3.0),
    ]
    assert card["mostUsed"][0]["link"]["params"] == {"days": "30"}


def test_connectivity_problems(insights):
    card = insights.compute_insights("all", False)["cards"]["connectivityProblems"]
    assert card["devices"] == 3
    assert card["weakSignal"]["count"] == 1
    assert (card["poorQuality"]["count"], card["poorQuality"]["measured"]) == (1, 2)
    assert card["onVpn"]["count"] == 2


def test_include_archived_widens_the_fleet(insights):
    card = insights.compute_insights("all", True)["cards"]["unmanagedDevices"]
    assert card["unmanaged"]["count"] == 3
