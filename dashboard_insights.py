"""The twelve dashboard insight cards, computed in Postgres.

Each card answers one question about the fleet ("which devices have gone a
month without a reboot?") with a few counts and a short top-N list. The three
dashboard apps used to work these out client-side from the bulk reports, which
meant every open dashboard pulled /system, /security, /installs and the rest in
full; on 2026-10-22 that held the API container at its memory limit until it
restarted. Here every card is an aggregate query over the per-device module
JSON, so what reaches Python is a handful of rows per card, never the modules.

The rules are the ones the web app applies (reportRules.ts and the insight
widgets), so a number on a card is the number of rows its deep link shows.
Every list item carries that deep link as ``{"path", "params"}``, using the
parameter names in the shared dashboard widget spec, so the three clients do
not each rebuild it.

A card is computed on its own pooled connection under its own statement
timeout. One that fails or times out comes back as ``{"error": "..."}``; the
others are unaffected.
"""

from __future__ import annotations

import math
import os
import re
import time as _time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import cmp_to_key
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence
from urllib.parse import quote

from dependencies import (
    _DB_POOL_MAX,
    canonicalize_app_name,
    get_db_connection,
    load_sql,
    logger,
)

# ── Tunables ────────────────────────────────────────────────────

#: Per-card ceiling. A card that runs longer is cancelled by Postgres and
#: reported as an error, so one slow table cannot hold the whole response.
STATEMENT_TIMEOUT_SECONDS = int(os.getenv("INSIGHTS_STATEMENT_TIMEOUT_SECONDS", "20"))

#: Cards computed at once. Each holds one pooled connection while it runs, so
#: this stays a small fraction of the pool the request handlers share.
CONCURRENCY = max(
    1, min(int(os.getenv("INSIGHTS_CONCURRENCY", "3")), max(1, _DB_POOL_MAX // 4))
)

TOP_N = 5

# ── Card rules shared with the web app ──────────────────────────

#: OS Currency: a version needs this many devices before it sets the bar, so
#: one beta Mac does not put the whole fleet behind (reportRules.ts).
OS_CURRENCY_MIN_DEVICES = 5
#: Install Health: an agent silent longer than this is reported (stale=1).
SILENT_AGENT_DAYS = 7
#: Expiring Certificates: the look-ahead window.
CERT_WINDOW_DAYS = 30
#: Unused Software: the usage window and the install floor for shelfware.
USAGE_DAYS = 30
MIN_INSTALLS_FOR_LEAST_USED = 10

CARD_KEYS = (
    "rebootDebt",
    "protectionGaps",
    "unmanagedDevices",
    "hardwareAtRisk",
    "installHealth",
    "checkinGaps",
    "osCurrency",
    "softwareRisk",
    "expiringCertificates",
    "localAdminExposure",
    "unusedSoftware",
    "connectivityProblems",
)

PLATFORMS = ("all", "macOS", "Windows")


def normalize_platform(value: Optional[str]) -> Optional[str]:
    """``all`` / ``macOS`` / ``Windows`` from any casing, or None if unknown."""
    v = (value or "all").strip().lower()
    if v in ("all", ""):
        return "all"
    if v in ("macos", "mac", "darwin"):
        return "macOS"
    if v in ("windows", "win"):
        return "Windows"
    return None


# ── Links ───────────────────────────────────────────────────────


def link(path: str, **params: Any) -> Dict[str, Any]:
    """A deep link in the shape every client renders as-is."""
    return {
        "path": path,
        "params": {k: str(v) for k, v in params.items() if v is not None},
    }


def device_link(serial: str) -> Dict[str, Any]:
    return link(f"/device/{quote(str(serial), safe='')}")


def app_usage_link(name: str) -> Dict[str, Any]:
    return link(f"/applications/usage/{quote(str(name), safe='')}", days=USAGE_DAYS)


# ── Small value helpers ─────────────────────────────────────────


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _pct(part: int, whole: int) -> int:
    """Rounded like JavaScript Math.round, so the apps and the API agree."""
    if not whole:
        return 0
    return int(math.floor(part * 100.0 / whole + 0.5))


def _iso(value: Any) -> Optional[str]:
    return (
        value.isoformat()
        if hasattr(value, "isoformat")
        else (str(value) if value else None)
    )


# ── SQL composition ─────────────────────────────────────────────

_TRUE = "('true', 't', 'yes', 'y', 'on', '1')"
_FALSE = "('false', 'f', 'no', 'n', 'off', '0')"
_NOT_STORED = (
    "NOT EXISTS (SELECT 1 FROM device_inventory_state st "
    "WHERE st.serial_number = UPPER(d.serial_number) AND st.state = 'storage')"
)


@dataclass(frozen=True)
class InsightsScope:
    platform: str
    include_archived: bool
    has_inventory_state: bool = True

    @property
    def params(self) -> Dict[str, Any]:
        return {"platform": self.platform, "include_archived": self.include_archived}


def card_sql(name: str, scope: InsightsScope) -> str:
    """A card query with the shared fleet scope and boolean vocabularies filled in."""
    fleet = load_sql("insights/fleet").replace(
        "/*NOT_STORED*/", _NOT_STORED if scope.has_inventory_state else "TRUE"
    )
    return (
        load_sql(f"insights/{name}")
        .replace("/*FLEET*/", fleet)
        .replace("{{TRUE}}", _TRUE)
        .replace("{{FALSE}}", _FALSE)
    )


Runner = Callable[..., List[Dict[str, Any]]]


def _make_runner(cursor, scope: InsightsScope) -> Runner:
    def run(name: str, **extra: Any) -> List[Dict[str, Any]]:
        params = {**scope.params, **extra}
        cursor.execute(card_sql(name, scope), params)
        cols = [c[0] for c in (cursor.description or [])]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    return run


# ── 1 Reboot & Update Debt ──────────────────────────────────────

UPTIME_BUCKETS = (
    ("lt1d", "< 1 day", "up_lt1d"),
    ("1-3d", "1-3 days", "up_1_3d"),
    ("3-7d", "3-7 days", "up_3_7d"),
    ("1-2w", "1-2 weeks", "up_1_2w"),
    ("2-4w", "2-4 weeks", "up_2_4w"),
    ("30d+", "30+ days", "up_30d"),
)


def shape_reboot_debt(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "devices": _int(row.get("devices")),
        "uptime30dPlus": {
            "count": _int(row.get("up_30d")),
            "link": link("/system", uptime="30d+"),
        },
        "uptime2to4w": {
            "count": _int(row.get("up_2_4w")),
            "link": link("/system", uptime="2-4w"),
        },
        "pendingUpdates": {
            "count": _int(row.get("pending")),
            "link": link("/system", pending="1-5,6-10,10+"),
        },
        "deferredUpdates": {
            "count": _int(row.get("deferred")),
            "link": link("/system", deferred=1),
        },
        "uptimeBuckets": [
            {
                "key": key,
                "label": label,
                "count": _int(row.get(col)),
                "link": link("/system", uptime=key),
            }
            for key, label, col in UPTIME_BUCKETS
        ],
    }


def card_reboot_debt(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_reboot_debt(run("reboot_debt")[0])


# ── 2 Protection Gaps ───────────────────────────────────────────

_PROTECTIONS = (
    ("encryption", "Disk encryption off", "encryption_off", "devices"),
    ("firewall", "Firewall off", "firewall_off", "devices"),
    ("antivirus", "Antivirus off", "antivirus_off", "antivirus_total"),
    ("sip", "System Integrity Protection off", "sip_off", "sip_total"),
    ("secureBoot", "Secure Boot off", "secure_boot_off", "secure_boot_total"),
)


def shape_protection_gaps(row: Dict[str, Any]) -> Dict[str, Any]:
    gaps = [
        {
            "key": key,
            "label": label,
            "count": _int(row.get(col)),
            "total": _int(row.get(total_col)),
            "link": link("/security", **{key: "off"}),
        }
        for key, label, col, total_col in _PROTECTIONS
        if _int(row.get(total_col)) > 0
    ]
    order = {key: i for i, (key, *_rest) in enumerate(_PROTECTIONS)}
    gaps.sort(key=lambda g: (-g["count"], order[g["key"]]))
    return {
        "devices": _int(row.get("devices")),
        "gaps": gaps,
        "withThreats": {
            "count": _int(row.get("with_threats")),
            "link": link("/security", threats=1),
        },
        "criticalCves": {
            "count": _int(row.get("critical_cves")),
            "link": link("/security", cve="critical"),
        },
    }


def card_protection_gaps(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_protection_gaps(run("security_flags")[0])


# ── 3 Unmanaged Devices ─────────────────────────────────────────


def shape_unmanaged(
    platform_rows: Sequence[Dict[str, Any]], recent_rows: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    total = sum(_int(r.get("devices")) for r in platform_rows)
    unmanaged = sum(_int(r.get("unmanaged")) for r in platform_rows)
    unenrolled = link("/management", enrolled=0)
    return {
        "devices": total,
        "unmanaged": {
            "count": unmanaged,
            "pct": _pct(unmanaged, total),
            "link": unenrolled,
        },
        "enrolledPct": _pct(total - unmanaged, total),
        "byPlatform": [
            {
                "platform": r.get("platform") or "Unknown",
                "count": _int(r.get("unmanaged")),
                "devices": _int(r.get("devices")),
                "link": unenrolled,
            }
            for r in sorted(
                platform_rows,
                key=lambda r: (-_int(r.get("unmanaged")), r.get("platform") or ""),
            )
            if _int(r.get("devices")) > 0
        ],
        "lastSeen": [
            {
                "key": "24h",
                "label": "Seen in the last 24 hours",
                "count": sum(_int(r.get("seen_24h")) for r in platform_rows),
                "link": unenrolled,
            },
            {
                "key": "7d",
                "label": "Seen 1-7 days ago",
                "count": sum(_int(r.get("seen_7d")) for r in platform_rows),
                "link": unenrolled,
            },
            {
                "key": "silent",
                "label": "Silent over 7 days",
                "count": sum(_int(r.get("silent")) for r in platform_rows),
                "link": unenrolled,
            },
        ],
        "recent": [
            {
                "serialNumber": r["serial"],
                "name": r.get("name") or r["serial"],
                "platform": r.get("platform"),
                "lastSeen": _iso(r.get("last_seen")),
                "link": device_link(r["serial"]),
            }
            for r in recent_rows
        ],
    }


def card_unmanaged(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_unmanaged(run("unmanaged"), run("unmanaged_recent", limit=TOP_N))


# ── 4 Hardware at Risk ──────────────────────────────────────────


def shape_hardware(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "devices": _int(row.get("devices")),
        "lowStorage": {
            "count": _int(row.get("low_storage")),
            "link": link("/hardware", storage="low"),
        },
        "lowMemory": {
            "count": _int(row.get("low_memory")),
            "link": link("/hardware", memory="le8"),
        },
        "intelMacs": {
            "count": _int(row.get("intel_macs")),
            "macs": _int(row.get("macs")),
            "link": link("/hardware", arch="Intel"),
        },
    }


def card_hardware(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_hardware(run("hardware_at_risk")[0])


# ── 5 Install Health ────────────────────────────────────────────


def _agent_record(sessions: Any, run_times: Any) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        k: v for k, v in (run_times or {}).items() if v is not None
    }
    record["sessions"] = sessions if isinstance(sessions, list) else []
    return record


def silent_agent_count(
    rows: Iterable[Dict[str, Any]], threshold_days: float = SILENT_AGENT_DAYS
) -> int:
    """Devices whose management agent last ran more than ``threshold_days`` before
    the device last checked in, by the same reading as /installs/filters."""
    # Imported here: routers.fleet imports this module's neighbours at load.
    from routers.fleet import agent_last_run, agent_stale_days

    silent = 0
    for r in rows:
        if r.get("has_cimian"):
            agent = _agent_record(r.get("cimian_sessions"), r.get("cimian_run"))
        elif r.get("has_munki"):
            agent = _agent_record(r.get("munki_sessions"), r.get("munki_run"))
        else:
            continue
        days = agent_stale_days(agent_last_run(agent), r.get("last_seen"))
        if days is not None and days > threshold_days:
            silent += 1
    return silent


def shape_install_health(
    counts: Dict[str, Any], failing: Sequence[Dict[str, Any]], silent_agents: int
) -> Dict[str, Any]:
    return {
        "devices": _int(counts.get("devices")),
        "withErrors": {
            "count": _int(counts.get("with_errors")),
            "link": link("/installs", filter="errors"),
        },
        "withWarnings": {
            "count": _int(counts.get("with_warnings")),
            "link": link("/installs", filter="warnings"),
        },
        "topFailing": [
            {
                "name": r["name"],
                "devices": _int(r.get("devices")),
                "link": link("/installs", item=r["name"], filter="errors"),
            }
            for r in failing
        ],
        "silentAgents": {
            "count": silent_agents,
            "thresholdDays": SILENT_AGENT_DAYS,
            "link": link("/installs", stale=1),
        },
    }


def card_install_health(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_install_health(
        run("install_counts")[0],
        run("install_items_failing", limit=TOP_N),
        silent_agent_count(run("install_agent_runs")),
    )


# ── 6 Check-in Gaps ─────────────────────────────────────────────

CHECKIN_HOURS = 24


def shape_checkin_gaps(
    outcome_counts: Sequence[Any],
    reasons: Sequence[Dict[str, Any]],
    silent: Dict[str, Any],
) -> Dict[str, Any]:
    rejected, retried, accepted = (list(outcome_counts) + [0, 0, 0])[:3]
    top = sorted(reasons, key=lambda r: -_int(r.get("count")))[:TOP_N]
    return {
        "hours": CHECKIN_HOURS,
        # ingest_failures rows are per check-in, recorded before a device is
        # known, so these three counts and the reasons cover every platform.
        "checkinsAllPlatforms": True,
        "rejected": {
            "count": _int(rejected),
            "link": link("/events/failures", hours=CHECKIN_HOURS),
        },
        "retried": {
            "count": _int(retried),
            "link": link("/events/failures", hours=CHECKIN_HOURS, outcome="retried"),
        },
        "accepted": {
            "count": _int(accepted),
            "link": link("/events/failures", hours=CHECKIN_HOURS, outcome="accepted"),
        },
        "reasons": [
            {
                "reason": r.get("reason"),
                "count": _int(r.get("count")),
                "devices": _int(r.get("devices")),
                "link": link(
                    "/events/failures", hours=CHECKIN_HOURS, reason=r.get("reason")
                ),
            }
            for r in top
        ],
        "stale": {
            "count": _int(silent.get("stale")),
            "link": link("/devices", status="stale"),
        },
        "missing": {
            "count": _int(silent.get("missing")),
            "link": link("/devices", status="missing"),
        },
    }


def card_checkin_gaps(run: Runner, scope: InsightsScope, cursor=None) -> Dict[str, Any]:
    params = {"hours": CHECKIN_HOURS, "serial": None}
    cursor.execute(load_sql("events/outcome_counts_ingest_failures"), params)
    counts = cursor.fetchone() or (0, 0, 0)
    cursor.execute(
        load_sql("events/summary_ingest_failures"), {**params, "outcome": "rejected"}
    )
    reasons = [
        {"reason": r[0], "count": r[1], "devices": r[2]} for r in cursor.fetchall()
    ]
    return shape_checkin_gaps(counts, reasons, run("silent_devices")[0])


# ── 7 OS Currency ───────────────────────────────────────────────

_VERSION_PREFIX = re.compile(r"^\d+(?:\.\d+)*")
_JS_FLOAT = re.compile(r"^\s*[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")


def version_parts(value: Any) -> List[int]:
    """'26.3.1 (a)' -> [26, 3, 1]."""
    m = _VERSION_PREFIX.match(str(value or ""))
    return [int(p) for p in m.group(0).split(".") if p] if m else []


def _js_num(value: Any) -> float:
    """JavaScript parseFloat semantics, as reportRules num() reads a string."""
    if isinstance(value, (int, float)):
        return float(value) if math.isfinite(value) else 0.0
    m = _JS_FLOAT.match(str(value or ""))
    if not m:
        return 0.0
    try:
        n = float(m.group(0))
    except ValueError:
        return 0.0
    return n if math.isfinite(n) else 0.0


def _compare(a: Sequence[float], b: Sequence[float]) -> float:
    for i in range(max(len(a), len(b))):
        d = (a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)
        if d:
            return d
    return 0


def _mac_ordinal(major: int) -> int:
    """Release order of a macOS major: Apple went from 15 straight to 26."""
    return major - 26 + 16 if major >= 26 else major


def _os_platform(os_platform: str, name: str) -> str:
    """The platform GET /system assigns a row."""
    n = (name or "").lower()
    if (os_platform or "").lower() == "darwin" or "macos" in n or "mac os" in n:
        return "macOS"
    if "windows" in n:
        return "Windows"
    return "Unknown"


def _operating_system(name: str, edition: str, display_version: str) -> str:
    """'Windows 11 Enterprise 24H2', built the way GET /system builds it."""
    text = name or ""
    if edition and edition not in text:
        text = f"{text} {edition}"
    if display_version:
        text = f"{text} {display_version}"
    return text.strip()


@dataclass
class OSRow:
    platform: str
    operating_system: str
    os_version: str
    build: str
    feature_update: str
    devices: int

    @classmethod
    def from_sql(cls, r: Dict[str, Any]) -> "OSRow":
        return cls(
            platform=_os_platform(r.get("os_platform") or "", r.get("os_name") or ""),
            operating_system=_operating_system(
                r.get("os_name") or "",
                r.get("edition") or "",
                r.get("display_version") or "",
            ),
            os_version=r.get("version") or "",
            build=(r.get("build") or "").strip(),
            feature_update=r.get("feature_update") or "",
            devices=_int(r.get("devices")),
        )

    def train(self):
        """(train, level): macOS major and full version, or Windows build and UBR."""
        if self.platform == "macOS":
            parts = version_parts(self.os_version)
            return (f"macOS {parts[0]}", parts) if parts else None
        if self.platform == "Windows":
            ubr = _js_num(self.feature_update)
            if not self.build or not ubr:
                return None
            return (f"Windows build {self.build}", [ubr])
        return None

    def version_key(self) -> str:
        """The value /system?osVersion= matches for this row."""
        if self.platform == "macOS":
            return re.sub(r"\s*\(.*\)$", "", self.os_version)
        m = re.search(r"Windows\s+(\d+)", self.operating_system)
        return f"{m.group(1)}.{self.build}" if m and self.build else ""

    def is_windows10(self) -> bool:
        return self.platform == "Windows" and bool(
            re.search(r"Windows\s+10\b", self.operating_system, re.I)
        )


def _level_key(level: Sequence[float]) -> str:
    return ".".join(str(int(p)) if float(p).is_integer() else str(p) for p in level)


def os_currency(
    rows: Sequence[OSRow],
    platform: str = "all",
    min_devices: int = OS_CURRENCY_MIN_DEVICES,
) -> Dict[str, Any]:
    """The OS Currency card. ``rows`` are the whole fleet: the rules are
    relative to it. The latest patch of a train is the highest version at
    least ``min_devices`` devices report (the highest seen when none does), and
    macOS more than two majors behind the newest major that many devices run is
    unsupported. Counting then covers only ``platform``."""
    levels: Dict[str, Dict[str, Dict[str, Any]]] = {}
    mac_majors: Dict[int, int] = {}
    for r in rows:
        t = r.train()
        if not t:
            continue
        train, level = t
        entry = levels.setdefault(train, {}).setdefault(
            _level_key(level), {"level": level, "count": 0}
        )
        entry["count"] += r.devices
        if r.platform == "macOS":
            o = _mac_ordinal(level[0])
            mac_majors[o] = mac_majors.get(o, 0) + r.devices

    latest: Dict[str, Sequence[float]] = {}
    for train, entries in levels.items():
        ordered = _sort_levels_desc(list(entries.values()))
        pick = next((e for e in ordered if e["count"] >= min_devices), ordered[0])
        latest[train] = pick["level"]

    majors = sorted(mac_majors.items(), key=lambda kv: -kv[0])
    newest = next(
        (m for m, n in majors if n >= min_devices), majors[0][0] if majors else 0
    )

    scoped = [r for r in rows if platform == "all" or r.platform == platform]
    rated = behind = unsupported = win10 = 0
    lagging: Dict[str, int] = {}
    for r in scoped:
        t = r.train()
        if t:
            rated += r.devices
            if _compare(t[1], latest[t[0]]) < 0:
                behind += r.devices
                key = r.version_key()
                if key:
                    lagging[key] = lagging.get(key, 0) + r.devices
        if r.platform == "macOS":
            major = (version_parts(r.os_version) or [0])[0]
            if major and _mac_ordinal(major) < newest - 2:
                unsupported += r.devices
        if r.is_windows10():
            win10 += r.devices

    top = sorted(lagging.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    return {
        "devices": sum(r.devices for r in scoped),
        "rated": rated,
        "onLatest": rated - behind,
        "pctOnLatest": _pct(rated - behind, rated),
        "minDevices": min_devices,
        "behind": {"count": behind, "link": link("/system", patch="behind")},
        "unsupportedMac": {
            "count": unsupported,
            "link": link("/system", os="unsupported"),
        },
        "windows10": {"count": win10, "link": link("/system", os="windows10")},
        "lagging": [
            {
                "version": v,
                "label": (
                    f"Windows {v.replace('.', ' build ', 1)}"
                    if re.match(r"^\d+\.\d{4,}$", v)
                    else f"macOS {v}"
                ),
                "devices": n,
                "link": link("/system", osVersion=v),
            }
            for v, n in top
        ],
    }


def _sort_levels_desc(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        entries, key=cmp_to_key(lambda x, y: _compare(y["level"], x["level"]))
    )


def card_os_currency(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    rows = [OSRow.from_sql(r) for r in run("os_versions", platform="all")]
    return os_currency(rows, scope.platform)


# ── 8 Software Risk ─────────────────────────────────────────────


def shape_software_risk(
    cves: Dict[str, Any], behind: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    return {
        "devices": _int(cves.get("devices")),
        "criticalCves": {
            "count": _int(cves.get("critical_cves")),
            "link": link("/security", cve="critical"),
        },
        "exploitedCves": {
            "count": _int(cves.get("exploited_cves")),
            "link": link("/security", cve="exploited"),
        },
        "itemsBehind": [
            {
                "name": r["name"],
                "devices": _int(r.get("devices")),
                "link": link("/installs", item=r["name"]),
            }
            for r in behind
        ],
    }


def card_software_risk(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_software_risk(
        run("security_flags")[0], run("install_items_behind", limit=TOP_N)
    )


# ── 9 Expiring Certificates ─────────────────────────────────────


def shape_certificates(
    row: Dict[str, Any], soonest: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    return {
        "devices": _int(row.get("devices")),
        "windowDays": CERT_WINDOW_DAYS,
        "expiring": {
            "certificates": _int(row.get("expiring_certs")),
            "devices": _int(row.get("expiring_devices")),
            "link": link("/security", certs="expiring"),
        },
        "expiredUser": {
            "devices": _int(row.get("expired_user_devices")),
            "link": link("/security", certs="expired"),
        },
        "soonest": [
            {
                "commonName": r["cn"],
                "daysUntilExpiry": int(math.floor(float(r.get("days") or 0) + 0.5)),
                "devices": _int(r.get("devices")),
                "link": link("/security", certSearch=r["cn"], certStatus="expiring"),
            }
            for r in soonest
        ],
    }


def card_certificates(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_certificates(
        run("certificates", window_days=CERT_WINDOW_DAYS)[0],
        run("certificates_soonest", window_days=CERT_WINDOW_DAYS, limit=TOP_N),
    )


# ── 10 Local Admin Exposure ─────────────────────────────────────

_JOINS = (
    ("entra", "Entra joined"),
    ("domain", "Domain joined"),
    ("hybrid", "Hybrid joined"),
    ("workgroup", "Workgroup"),
)


def shape_local_admins(
    platform_rows: Sequence[Dict[str, Any]], top: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    def total(col: str) -> int:
        return sum(_int(r.get(col)) for r in platform_rows)

    extra = link("/identity", admins="extra")
    return {
        "devices": total("devices"),
        "extraAdmins": {"count": total("extra_admins"), "link": extra},
        "byAdminCount": [
            {
                "key": "2",
                "label": "2 admins",
                "count": total("admins_2"),
                "link": extra,
            },
            {
                "key": "3",
                "label": "3 admins",
                "count": total("admins_3"),
                "link": extra,
            },
            {
                "key": "4+",
                "label": "4 or more admins",
                "count": total("admins_4_plus"),
                "link": extra,
            },
        ],
        "topDevices": [
            {
                "serialNumber": r["serial"],
                "name": r.get("name") or r["serial"],
                "platform": r.get("platform"),
                "admins": _int(r.get("admins")),
                "link": device_link(r["serial"]),
            }
            for r in top
        ],
        "join": [
            {
                "key": key,
                "label": label,
                "count": total(key),
                "link": link("/identity", join=key),
            }
            for key, label in _JOINS
        ],
        "workgroup": {
            "count": total("workgroup"),
            "link": link("/identity", join="workgroup"),
            "byPlatform": [
                {
                    "platform": r.get("platform") or "Unknown",
                    "count": _int(r.get("workgroup")),
                }
                for r in platform_rows
                if _int(r.get("workgroup")) > 0
            ],
        },
    }


def card_local_admins(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_local_admins(
        run("identity_admins"), run("identity_top_admins", limit=TOP_N)
    )


# ── 11 Unused Software ──────────────────────────────────────────


def fold_name(raw: str, installed: bool = False) -> str:
    """The usage bucket a raw app name belongs to, lower-cased for matching.
    Installed names drop a trailing .app the way fold_installed_devices does."""
    name = (raw or "").strip()
    if installed and name.lower().endswith(".app"):
        name = name[:-4].strip()
    if not name:
        return ""
    return (canonicalize_app_name(name) or name).strip()


def shape_unused_software(
    usage: Sequence[Dict[str, Any]], installed: Dict[str, int]
) -> Dict[str, Any]:
    """``usage`` rows carry a display name in ``app`` and a lower-cased fold key
    in ``key``; ``installed`` maps fold key to installed device count."""
    apps = []
    for r in usage:
        apps.append(
            {
                "name": r["app"],
                "totalHours": round(float(r.get("total_seconds") or 0) / 3600.0, 1),
                "activeHours": round(float(r.get("active_seconds") or 0) / 3600.0, 1),
                "devices": _int(r.get("device_count")),
                "activeDevices": _int(r.get("active_device_count")),
                "installedDevices": installed.get(r["key"], 0),
            }
        )
    most = sorted(apps, key=lambda a: (-a["totalHours"], a["name"]))[:TOP_N]
    candidates = [
        a for a in apps if a["installedDevices"] >= MIN_INSTALLS_FOR_LEAST_USED
    ]
    for a in candidates:
        a["usageRate"] = round(a["activeDevices"] / a["installedDevices"], 3)
    least = sorted(
        candidates, key=lambda a: (a["usageRate"], -a["installedDevices"], a["name"])
    )[:TOP_N]
    return {
        "days": USAGE_DAYS,
        "minInstalls": MIN_INSTALLS_FOR_LEAST_USED,
        "leastUsed": [
            {
                k: a[k]
                for k in ("name", "activeDevices", "installedDevices", "usageRate")
            }
            | {"link": app_usage_link(a["name"])}
            for a in least
        ],
        "mostUsed": [
            {k: a[k] for k in ("name", "totalHours", "activeHours", "activeDevices")}
            | {"link": app_usage_link(a["name"])}
            for a in most
        ],
    }


def card_unused_software(
    run: Runner, scope: InsightsScope, today: Optional[date] = None
) -> Dict[str, Any]:
    cutoff = (today or datetime.now(timezone.utc).date()) - timedelta(days=USAGE_DAYS)

    usage_names = [r["app_name"] for r in run("usage_app_names", cutoff=cutoff)]
    display: Dict[str, str] = {}
    usage_raw, usage_keys = [], []
    for raw in usage_names:
        folded = fold_name(raw)
        if not folded:
            continue
        key = folded.lower()
        display.setdefault(key, folded)
        usage_raw.append(raw)
        usage_keys.append(key)
    if not usage_raw:
        return shape_unused_software([], {})

    wanted = set(usage_keys)
    inst_raw, inst_keys = [], []
    for r in run("installed_app_names"):
        key = fold_name(r["app_name"], installed=True).lower()
        if key in wanted:
            inst_raw.append(r["app_name"])
            inst_keys.append(key)

    usage = run(
        "usage_by_app", cutoff=cutoff, raw_names=usage_raw, folded_names=usage_keys
    )
    installed: Dict[str, int] = {}
    if inst_raw:
        for r in run("installed_by_app", raw_names=inst_raw, folded_names=inst_keys):
            installed[r["app"]] = _int(r.get("installed_devices"))
    for r in usage:
        r["key"] = r["app"]
        r["app"] = display.get(r["app"], r["app"])
    return shape_unused_software(usage, installed)


# ── 12 Connectivity Problems ────────────────────────────────────


def shape_connectivity(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "devices": _int(row.get("devices")),
        "weakSignal": {
            "count": _int(row.get("weak_signal")),
            "link": link("/network", signal="weak"),
        },
        # The network report has no filter for these two yet; the link opens it unfiltered.
        "poorQuality": {
            "count": _int(row.get("poor_quality")),
            "measured": _int(row.get("quality_measured")),
            "link": link("/network"),
        },
        "onVpn": {"count": _int(row.get("on_vpn")), "link": link("/network")},
    }


def card_connectivity(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_connectivity(run("network_problems")[0])


# ── Orchestration ───────────────────────────────────────────────

CARD_FUNCTIONS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "rebootDebt": card_reboot_debt,
    "protectionGaps": card_protection_gaps,
    "unmanagedDevices": card_unmanaged,
    "hardwareAtRisk": card_hardware,
    "installHealth": card_install_health,
    "checkinGaps": card_checkin_gaps,
    "osCurrency": card_os_currency,
    "softwareRisk": card_software_risk,
    "expiringCertificates": card_certificates,
    "localAdminExposure": card_local_admins,
    "unusedSoftware": card_unused_software,
    "connectivityProblems": card_connectivity,
}


def _error_text(exc: BaseException) -> str:
    """A short reason for the card error state. Never SQL or connection detail."""
    text = str(exc)
    if "57014" in text or "statement timeout" in text:
        return f"Timed out after {STATEMENT_TIMEOUT_SECONDS}s"
    if "connection" in text.lower():
        return "Database unavailable"
    return "Could not compute this card"


def run_card(key: str, scope: InsightsScope) -> Dict[str, Any]:
    """One card on its own connection, under its own statement timeout.
    Any failure becomes ``{"error": ...}`` for this card alone."""
    fn = CARD_FUNCTIONS[key]
    conn = None
    t0 = _time.monotonic()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # SET LOCAL lasts until this transaction ends; closing the connection
        # rolls back, so the pooled connection returns with its own timeout.
        cursor.execute(
            f"SET LOCAL statement_timeout = '{int(STATEMENT_TIMEOUT_SECONDS * 1000)}ms'"
        )
        run = _make_runner(cursor, scope)
        if key == "checkinGaps":
            result = fn(run, scope, cursor=cursor)
        else:
            result = fn(run, scope)
        logger.info(f"[INSIGHTS] {key}: {_time.monotonic() - t0:.3f}s")
        return result
    except Exception as exc:
        logger.error(
            f"[INSIGHTS] {key} failed after {_time.monotonic() - t0:.3f}s: {exc}"
        )
        return {"error": _error_text(exc)}
    finally:
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def _has_inventory_state_table() -> bool:
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT to_regclass('device_inventory_state') IS NOT NULL")
        row = cursor.fetchone()
        return bool(row and row[0])
    except Exception as exc:
        logger.warning(f"[INSIGHTS] Could not check for device_inventory_state: {exc}")
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def compute_insights(
    platform: str = "all", include_archived: bool = False
) -> Dict[str, Any]:
    """Every card for one platform scope. Synchronous: run it off the event loop."""
    t0 = _time.monotonic()
    scope = InsightsScope(platform, include_archived, _has_inventory_state_table())
    with ThreadPoolExecutor(
        max_workers=CONCURRENCY, thread_name_prefix="insights"
    ) as pool:
        futures = {key: pool.submit(run_card, key, scope) for key in CARD_KEYS}
        cards = {key: futures[key].result() for key in CARD_KEYS}
    elapsed = _time.monotonic() - t0
    failed = [k for k, v in cards.items() if "error" in v]
    logger.info(
        f"[INSIGHTS] platform={platform} includeArchived={include_archived}: "
        f"{elapsed:.3f}s, {len(failed)} failed{(' (' + ', '.join(failed) + ')') if failed else ''}"
    )
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "platform": platform,
        "includeArchived": include_archived,
        "computeSeconds": round(elapsed, 3),
        "cards": cards,
    }
