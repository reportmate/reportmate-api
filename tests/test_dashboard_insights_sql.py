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

from log_tails import stamp_log_summaries

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

def munki_line(when, text):
    return when.strftime("%b %d %Y %H:%M:%S +0000 ") + text


def convention_line(when, level, text):
    return when.strftime("[%Y-%m-%d %H:%M:%S] ") + f"{level}  {text}"


def root(tool, lines, name="", file="run.log"):
    return {"tool": tool, "name": name, "tails": [{"file": file, "lines": lines}]}


# Management log tails. Ingest stamps levelSummary on each root; the seed
# runs the same stamp so the card reads what production would.
MANAGEMENT = {
    "SAMPLE1": {"logs": {"roots": [
        root("installs", [
            munki_line(ago(hours=1), "ERROR: Download of SAMPLE App failed: 404"),
            ago(hours=1).strftime("%Y-%m-%dT%H:%M:%S.123 -07:00") + " [ERR] Device registration failed for 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            munki_line(ago(hours=2), "ERROR: Could not process item SAMPLE Tool"),
            munki_line(ago(hours=2), "WARNING: SAMPLE warning"),
            munki_line(ago(days=3), "ERROR: An old failure outside the window"),
            munki_line(ago(hours=1), "Finished session"),
        ], name="Managed Installs"),
        root("mdm", [ago(hours=2).strftime("%Y-%m-%d %H:%M:%S") + ":123 | IntuneMdmAgent | E | 77 | SAMPLE | check-in failed"],
             name="Intune"),
    ]}},
    "SAMPLE2": {"mdmEnrollment": {"isEnrolled": True, "serverUrl": "https://sample.jamfcloud.com/mdm"},
                "logs": {"roots": [
        # Named after the MDM this device is enrolled in, so not a management tool.
        root("jamf", [munki_line(ago(hours=2), "ERROR: SAMPLE Jamf agent failure")], name="Jamf Pro"),
        root("installs", [
            munki_line(ago(hours=3), "ERROR: Download of SAMPLE App failed: 500"),
            munki_line(ago(hours=3), "WARNING: Another SAMPLE warning"),
        ]),
    ]}},
    "SAMPLE8": {"logs": {"roots": [
        root("installs", [convention_line(ago(hours=1), "ERROR", r"Failed to read C:\ProgramData\SAMPLE\cache.json")]),
        root("bootstrap", ['<![LOG[SAMPLE step failed]LOG]!><time="' + ago(hours=3).strftime("%H:%M:%S") + '.000+000" date="'
                           + ago(hours=3).strftime("%m-%d-%Y") + '" component="SAMPLE" context="" type="3" thread="1" file="">'],
             file="bootstrap.log"),
    ]}},
    "SAMPLE11": {"logs": {"roots": [root("installs", [munki_line(ago(hours=1), "ERROR: archived device")])]}},
}

INVENTORY = {
    "SAMPLE1": {"usage": "Shared", "catalog": "Lab"},
    "SAMPLE2": {"usage": "Assigned", "catalog": "Staff"},
    "SAMPLE8": {"usage": "Assigned", "catalog": "Staff"},
}

HARDWARE = {
    "SAMPLE1": {"storage": [{"capacity": 1000, "freeSpace": 30, "isInternal": True}]},
    "SAMPLE2": {"storage": [{"size": 1000, "freeSpace": 500},
                            {"capacity": 1000, "freeSpace": 1, "isInternal": False}]},
    "SAMPLE8": {"storage": [{"capacity": 512e9, "freeSpace": 40e9}]},
    "SAMPLE9": {"drives": [{"capacity": 2e12, "freeSpace": 3e11}]},
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
                    {"itemName": "Zoom", "reportmateStatus": "pending"},
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
    "SAMPLE2": {"users": [{"isAdmin": True}], "platformSSOUsers": {"deviceRegistered": True}},
    "SAMPLE3": {"users": [{"isAdmin": True}], "directoryServices": {"activeDirectory": {"bound": True}}},
    "SAMPLE4": {"users": [], "directoryServices": {"activeDirectory": {"isDomainJoined": True}},
                "domainTrust": {"trustStatus": "Broken"}},
    "SAMPLE10": {"users": [], "directoryServices": {"workgroup": "WORKGROUP"}},
    "SAMPLE8": {
        "domainTrust": {"trustStatus": "Healthy"},
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
        ("management", {k: stamp_log_summaries(v) for k, v in MANAGEMENT.items()}),
        ("inventory", INVENTORY),
        ("hardware", HARDWARE),
        ("identity", IDENTITY),
        ("network", NETWORK),
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
    monkeypatch.setattr(dashboard_insights, "_inventory_state_checked", None)
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


def test_connectivity_problems(insights):
    card = insights.compute_insights("all", False)["cards"]["connectivityProblems"]
    assert card["devices"] == 3
    assert card["weakSignal"]["count"] == 1
    assert (card["poorQuality"]["count"], card["poorQuality"]["measured"]) == (1, 2)
    assert card["onVpn"]["count"] == 2


def test_install_health(insights):
    card = insights.compute_card("installHealth")
    assert (card["withErrors"]["count"], card["withWarnings"]["count"]) == (2, 1)
    assert (card["errorItems"]["count"], card["warningItems"]["count"]) == (2, 1)
    assert (card["pending"]["items"], card["pending"]["devices"]) == (1, 1)
    assert card["pending"]["link"]["params"] == {"filter": "pending"}
    assert card["silentAgents"]["count"] == 2
    assert card["topFailing"] == [{
        "name": "Firefox", "devices": 3,
        "link": {"path": "/installs", "params": {"item": "Firefox", "filter": "errors"}},
    }]
    agents = {a["agent"]: a for a in card["byAgent"]}
    munki, cimian = agents["munki"], agents["cimian"]
    assert (munki["devices"], munki["withErrors"]["count"], munki["withWarnings"]["count"]) == (2, 1, 1)
    assert (cimian["devices"], cimian["withErrors"]["count"], cimian["pending"]["items"]) == (1, 1, 1)
    assert (munki["silentAgents"]["count"], cimian["silentAgents"]["count"]) == (1, 1)
    assert munki["withErrors"]["link"]["params"] == {"filter": "errors", "agent": "munki"}
    assert cimian["pending"]["link"]["params"] == {"filter": "pending", "agent": "cimian"}


def test_install_health_platform_drops_the_other_agent(insights):
    card = insights.compute_card("installHealth", "macOS")
    assert [a["agent"] for a in card["byAgent"]] == ["munki"]
    assert card["withErrors"]["count"] == 1


def test_management_tool_logs(insights):
    card = insights.compute_card("managementToolLogs")
    tools = {t["name"]: t for t in card["tools"]}
    # The MDM agent is out: tagged mdm on SAMPLE1, and named after the
    # device's own MDM (Jamf, from its enrollment URL) on SAMPLE2.
    assert set(tools) == {"Munki", "Cimian", "BootstrapMate"}
    munki = tools["Munki"]
    assert (munki["devices"], munki["devicesWithErrors"], munki["devicesWithWarnings"]) == (2, 2, 2)
    assert munki["errorLines"] == 4
    assert munki["link"] == {"path": "/devices", "params": {"tool": "installs", "level": "error", "platform": "macOS"}}
    assert tools["Cimian"]["devicesWithErrors"] == 1
    assert tools["BootstrapMate"]["link"]["params"] == {"tool": "bootstrap", "level": "error"}
    assert card["tools"][0]["name"] == "Munki"

    top = card["topErrors"][0]
    assert (top["name"], top["devices"]) == ("Munki", 2)
    assert top["message"].startswith("Download of SAMPLE App failed") and "404" not in top["message"]
    assert top["sampleDevice"]["link"] == {
        "path": "/device/SAMPLE1",
        "params": {"tab": "management", "tool": "installs", "level": "error"},
    }
    messages = [m["message"] for m in card["topErrors"]]
    assert "Device registration failed for <guid>" in messages
    assert len(messages) == len(set((m["tool"], m["message"]) for m in card["topErrors"]))
    assert not any("archived" in m or "old failure" in m or "Jamf" in m or "check-in" in m for m in messages)


def test_management_tool_errors_is_an_alias(insights):
    assert "managementToolErrors" in insights.CARD_ALIASES


def test_storage(insights):
    card = insights.compute_card("storage")
    assert card["devices"] == 4
    assert {b["key"]: b["count"] for b in card["freeSpace"]} == {"lt5": 1, "5-10": 1, "10-20": 1, "20+": 1}
    assert card["freeSpace"][0]["link"] == {"path": "/hardware", "params": {"storage": "lt5"}}
    assert card["lowStorage"]["count"] == 2
    assert {p["platform"]: p["count"] for p in card["lowStorage"]["byPlatform"]} == {"macOS": 1, "Windows": 1}
    assert card["lowStorage"]["byPlatform"][0]["link"]["params"] == {"storage": "low", "platform": "macOS"}
    assert {c["key"]: c["count"] for c in card["capacity"]} == {"le256": 2, "512": 1, "1t": 0, "2t+": 1}
    assert card["capacity"][3]["link"]["params"] == {"capacity": "2t+"}
    assert [d["serialNumber"] for d in card["fullest"]] == ["SAMPLE1", "SAMPLE8", "SAMPLE9", "SAMPLE2"]
    assert card["fullest"][0]["freePct"] == 3.0


def test_directory_services(insights):
    card = insights.compute_card("directoryServices")
    assert card["devices"] == 7
    segments = {seg["key"]: seg for seg in card["segments"]}
    assert [seg["key"] for seg in card["segments"]] == ["Cloud Joined", "Domain Joined", "Standard", "Unjoined"]
    assert {k: v["count"] for k, v in segments.items()} == {
        "Cloud Joined": 2, "Domain Joined": 3, "Standard": 1, "Unjoined": 1,
    }
    assert {t["key"]: t["count"] for t in segments["Domain Joined"]["trust"]} == {
        "Trusted": 1, "Unconfirmed": 1, "Broken": 1,
    }
    assert segments["Cloud Joined"]["link"] == {"path": "/identity", "params": {"directory": "Cloud Joined"}}
    assert segments["Domain Joined"]["trust"][2]["link"]["params"] == {"directory": "Broken"}
    assert (card["extraAdmins"]["count"], card["shared"]["count"], card["assigned"]["count"]) == (2, 1, 2)


def test_directory_services_follows_the_platform_toggle(insights):
    card = insights.compute_card("directoryServices", "Windows")
    assert {seg["key"]: seg["count"] for seg in card["segments"]} == {
        "Cloud Joined": 1, "Domain Joined": 1, "Standard": 0, "Unjoined": 1,
    }
    assert card["segments"][3]["link"]["params"] == {"directory": "Unjoined", "platform": "Windows"}
    assert card["extraAdmins"]["link"]["params"] == {"admins": "extra", "platform": "Windows"}


def test_app_usage(insights):
    card = insights.compute_app_usage()
    assert [(a["name"], a["totalHours"]) for a in card["apps"]] == [
        (insights.fold_name("Slack"), 10.0), (insights.fold_name("Firefox"), 3.0),
    ]
    assert card["available"]["usages"] == [{"value": "Assigned", "devices": 2}, {"value": "Shared", "devices": 1}]
    assert card["available"]["catalogs"] == [{"value": "Staff", "devices": 2}, {"value": "Lab", "devices": 1}]

    scoped = insights.compute_app_usage("all", ["Assigned"], [], 30)
    assert [(a["name"], a["totalHours"]) for a in scoped["apps"]] == [(insights.fold_name("Firefox"), 1.0)]
    assert scoped["apps"][0]["link"]["params"] == {"days": "30", "usages": "Assigned"}
    assert scoped["filters"] == {"usages": ["Assigned"], "catalogs": []}


def test_include_archived_widens_the_fleet(insights):
    assert insights.compute_card("protectionGaps", "all", True)["devices"] == 5
    assert insights.compute_card("protectionGaps", "all", False)["devices"] == 4


def test_every_card_carries_generated_at(insights):
    for key in insights.CARD_KEYS:
        assert insights.compute_card(key)["generatedAt"]


def test_management_tool_error_devices(insights):
    result = insights.compute_tool_devices("installs", "error", 24, "all")
    assert [(d["serialNumber"], d["count"]) for d in result["devices"]] == [
        ("SAMPLE1", 3), ("SAMPLE8", 1), ("SAMPLE2", 1),
    ]
    first = result["devices"][0]
    assert first["deviceName"] == "SAMPLE1-name" and first["platform"] == "macOS"
    assert first["lastAt"] == ago(hours=1).strftime("%Y-%m-%dT%H:00:00Z")
    assert first["link"] == {"path": "/device/SAMPLE1",
                             "params": {"tab": "management", "tool": "installs", "level": "error"}}
    assert (result["tool"], result["level"], result["hours"]) == ("installs", "error", 24)

    mac = insights.compute_tool_devices("INSTALLS", "error", 24, "macOS")
    assert [d["serialNumber"] for d in mac["devices"]] == ["SAMPLE1", "SAMPLE2"]
    warnings = insights.compute_tool_devices("installs", "warning", 24, "all")
    assert sorted(d["serialNumber"] for d in warnings["devices"]) == ["SAMPLE1", "SAMPLE2"]
    assert insights.compute_tool_devices("mdm")["devices"] == []
    assert insights.compute_tool_devices("jamf")["devices"] == []
    week = insights.compute_tool_devices("installs", "error", 168, "macOS")
    assert [(d["serialNumber"], d["count"]) for d in week["devices"]][0] == ("SAMPLE1", 4)
    assert insights.compute_tool_devices("nosuchtool")["devices"] == []
