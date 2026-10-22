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
#: App Usage: the default usage window.
USAGE_DAYS = 30

CARD_KEYS = (
    "installHealth",
    "rebootDebt",
    "protectionGaps",
    "managementToolLogs",
    "storage",
    "checkinGaps",
    "osCurrency",
    "softwareRisk",
    "expiringCertificates",
    "directoryServices",
    "connectivityProblems",
)

PLATFORMS = ("all", "macOS", "Windows")

#: Old card keys still answered for one release, mapped to their new key.
CARD_ALIASES = {"managementToolErrors": "managementToolLogs"}


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
#: JavaScript falsy JSON values, for rules ported from the web app as-is.
_JS_FALSY = "('false'::jsonb, '0'::jsonb, '\"\"'::jsonb, 'null'::jsonb)"
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


def card_sql(name: str, scope: InsightsScope, select: Optional[str] = None) -> str:
    """A card query with the shared fleet scope and boolean vocabularies filled
    in. ``select`` names a fragment that replaces /*STORAGE_SELECT*/."""
    fleet = load_sql("insights/fleet").replace(
        "/*NOT_STORED*/", _NOT_STORED if scope.has_inventory_state else "TRUE"
    )
    text = load_sql(f"insights/{name}").replace("/*MANAGEMENT_ROOTS*/", load_sql("insights/management_roots"))
    if select:
        text = text.replace("/*STORAGE_SELECT*/", load_sql(f"insights/{select}"))
    return (
        text
        .replace("/*FLEET*/", fleet)
        .replace("{{TRUE}}", _TRUE)
        .replace("{{JS_FALSY}}", _JS_FALSY)
        .replace("{{FALSE}}", _FALSE)
    )


Runner = Callable[..., List[Dict[str, Any]]]


def _make_runner(cursor, scope: InsightsScope) -> Runner:
    def run(name: str, _select: Optional[str] = None, **extra: Any) -> List[Dict[str, Any]]:
        params = {**scope.params, **extra}
        cursor.execute(card_sql(name, scope, _select), params)
        cols = [c[0] for c in (cursor.description or [])]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]

    return run


# ── Reboot & Update Debt ──────────────────────────────────────

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


# ── Protection Gaps ───────────────────────────────────────────

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


# ── Management Tools Logs ───────────────────────────────────────

#: The window the card counts over, in hours.
TOOL_WINDOW_HOURS = 24

#: Product names per log root, as the Mac app labels the tabs
#: (ManagementLogs.Root.productNames): (macOS, Windows).
TOOL_PRODUCTS = {
    "installs": ("Munki", "Cimian"),
    "bootstrap": ("BootstrapMate", "BootstrapMate"),
    "reports": ("ReportMate", "ReportMate"),
    "state": ("Outset", "StartSet"),
    "encryption": ("Crypt", "Crypt"),
    "users": ("ManageUsers", "ManageUsers"),
    "utilities": ("Utilities", "Utilities"),
    "notifications": ("swiftDialog", "csharpDialog"),
    "installer": ("Installer", "Installer"),
}


def tool_product(tool: str, platform: Optional[str], mdm_name: Optional[str] = None) -> str:
    """The product behind a log root on a platform: Munki or Cimian for installs."""
    if tool == "mdm":
        return (mdm_name or "").strip() or "MDM"
    names = TOOL_PRODUCTS.get(tool)
    if not names:
        return tool[:1].upper() + tool[1:]
    return names[1] if (platform or "").lower().startswith("win") else names[0]


def _tool_platform_specific(tool: str) -> bool:
    names = TOOL_PRODUCTS.get(tool)
    return bool(names) and names[0] != names[1]


def _tool_link(tool: str, level: str, platform: Optional[str]) -> Dict[str, Any]:
    return link("/devices", tool=tool, level=level,
                platform=platform if _tool_platform_specific(tool) else None)


def tool_device_link(serial: str, tool: str, level: str = "error") -> Dict[str, Any]:
    """The device page Management tab, log viewer on that tool and level."""
    return link(f"/device/{quote(str(serial), safe='')}", tab="management", tool=tool, level=level)


def window_start_hour(now: Optional[datetime] = None, hours: int = TOOL_WINDOW_HOURS) -> str:
    """The first UTC hour key inside the window, comparable to levelSummary keys."""
    return ((now or datetime.now(timezone.utc)) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H")


def shape_management_tools(rows: Sequence[Dict[str, Any]], messages: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    tools: Dict[Any, Dict[str, Any]] = {}
    for r in rows:
        tool = r.get("tool") or ""
        product = tool_product(tool, r.get("platform"), r.get("mdm_name"))
        key = (tool, product)
        entry = tools.setdefault(key, {
            "tool": tool, "name": product,
            "platform": r.get("platform") if _tool_platform_specific(tool) else None,
            "devices": 0, "devicesWithErrors": 0, "devicesWithWarnings": 0,
            "errorLines": 0, "warningLines": 0,
        })
        entry["devices"] += _int(r.get("devices"))
        entry["devicesWithErrors"] += _int(r.get("devices_with_errors"))
        entry["devicesWithWarnings"] += _int(r.get("devices_with_warnings"))
        entry["errorLines"] += _int(r.get("error_lines"))
        entry["warningLines"] += _int(r.get("warning_lines"))
    ordered = sorted(tools.values(), key=lambda t: (-t["devicesWithErrors"], -t["errorLines"],
                                                    -t["devicesWithWarnings"], t["name"]))
    for t in ordered:
        t["link"] = _tool_link(t["tool"], "error", t["platform"])
        t["warningsLink"] = _tool_link(t["tool"], "warning", t["platform"])
    return {
        "windowHours": TOOL_WINDOW_HOURS,
        "tools": ordered,
        "topErrors": top_tool_messages(messages),
    }


def top_tool_messages(messages: Sequence[Dict[str, Any]], limit: int = TOP_N) -> List[Dict[str, Any]]:
    """Group stored messages by tool and message, after stripping any stamp,
    offset or level prefix an older summary kept, and sum devices and lines."""
    from log_tails import strip_message_prefix

    grouped: Dict[Any, Dict[str, Any]] = {}
    for m in messages:
        tool = m.get("tool") or ""
        text = strip_message_prefix(m.get("message") or "")
        if not text:
            continue
        g = grouped.setdefault((tool, text), {"tool": tool, "message": text, "devices": 0, "lines": 0,
                                              "platforms": set(), "sample": m.get("sample_serial")})
        g["devices"] += _int(m.get("devices"))
        g["lines"] += _int(m.get("lines"))
        g["platforms"].update(p for p in (m.get("platforms") or []) if p)
        if m.get("sample_serial") and (not g["sample"] or m["sample_serial"] < g["sample"]):
            g["sample"] = m["sample_serial"]
    ordered = sorted(grouped.values(), key=lambda g: (-g["devices"], -g["lines"], g["tool"], g["message"]))[:limit]
    out = []
    for g in ordered:
        platforms = sorted(g["platforms"])
        single = platforms[0] if len(platforms) == 1 else None
        names = [] if not platforms else sorted({tool_product(g["tool"], p) for p in platforms})
        out.append({
            "message": g["message"],
            "tool": g["tool"],
            "name": " / ".join(names) if names else tool_product(g["tool"], None),
            "devices": g["devices"],
            "lines": g["lines"],
            "link": _tool_link(g["tool"], "error", single),
            "sampleDevice": {
                "serialNumber": g["sample"],
                "link": tool_device_link(g["sample"], g["tool"]),
            },
        })
    return out


def card_management_tools(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    since = window_start_hour()
    return shape_management_tools(
        run("management_tool_errors", since_hour=since),
        run("management_tool_messages", since_hour=since, limit=200),
    )


# ── Storage ─────────────────────────────────────────────────────

FREE_BUCKETS = (
    ("lt5", "Under 5% free", "free_lt5"),
    ("5-10", "5-10% free", "free_5_10"),
    ("10-20", "10-20% free", "free_10_20"),
    ("20+", "20% or more free", "free_20_plus"),
)
CAPACITY_BUCKETS = (
    ("le256", "256 GB or less", "cap_le256"),
    ("512", "512 GB", "cap_512"),
    ("1t", "1 TB", "cap_1t"),
    ("2t+", "2 TB or more", "cap_2t_plus"),
)


def shape_storage(platform_rows: Sequence[Dict[str, Any]], fullest: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    def total(col: str) -> int:
        return sum(_int(r.get(col)) for r in platform_rows)

    def low(r: Dict[str, Any]) -> int:
        return _int(r.get("free_lt5")) + _int(r.get("free_5_10"))

    return {
        "devices": total("devices"),
        "freeSpace": [
            {"key": k, "label": label, "count": total(col), "link": link("/hardware", storage=k)}
            for k, label, col in FREE_BUCKETS
        ],
        "lowStorage": {
            "count": sum(low(r) for r in platform_rows),
            "link": link("/hardware", storage="low"),
            "byPlatform": [
                {"platform": r.get("platform") or "Unknown", "count": low(r),
                 "link": link("/hardware", storage="low", platform=r.get("platform") or "Unknown")}
                for r in platform_rows
            ],
        },
        "capacity": [
            {"key": k, "label": label, "count": total(col), "link": link("/hardware", capacity=k)}
            for k, label, col in CAPACITY_BUCKETS
        ],
        "fullest": [
            {
                "serialNumber": r["serial"],
                "name": r.get("name") or r["serial"],
                "platform": r.get("platform"),
                "freePct": round(float(r.get("free_ratio") or 0) * 100, 1),
                "freeBytes": int(r.get("free_bytes") or 0),
                "totalBytes": int(r.get("total_bytes") or 0),
                "link": device_link(r["serial"]),
            }
            for r in fullest
        ],
    }


def card_storage(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_storage(
        run("storage_devices", _select="storage"),
        run("storage_devices", _select="storage_fullest", limit=TOP_N),
    )


# ── Install Health ──────────────────────────────────────────────

INSTALL_AGENTS = (("munki", "Munki", "macOS"), ("cimian", "Cimian", "Windows"))


def _agent_record(sessions: Any, run_times: Any) -> Dict[str, Any]:
    record: Dict[str, Any] = {k: v for k, v in (run_times or {}).items() if v is not None}
    record["sessions"] = sessions if isinstance(sessions, list) else []
    return record


def silent_agent_counts(
    rows: Iterable[Dict[str, Any]], threshold_days: float = SILENT_AGENT_DAYS
) -> Dict[str, int]:
    """Per agent, devices whose agent last ran more than ``threshold_days`` before
    the device last checked in, by the same reading as /installs/filters."""
    # Imported here: routers.fleet imports this module's neighbours at load.
    from routers.fleet import agent_last_run, agent_stale_days

    silent = {"munki": 0, "cimian": 0}
    for r in rows:
        if r.get("has_cimian"):
            name, agent = "cimian", _agent_record(r.get("cimian_sessions"), r.get("cimian_run"))
        elif r.get("has_munki"):
            name, agent = "munki", _agent_record(r.get("munki_sessions"), r.get("munki_run"))
        else:
            continue
        days = agent_stale_days(agent_last_run(agent), r.get("last_seen"))
        if days is not None and days > threshold_days:
            silent[name] += 1
    return silent


def shape_install_health(
    counts: Dict[str, Any],
    failing: Sequence[Dict[str, Any]],
    silent: Dict[str, int],
    pending: Sequence[Dict[str, Any]],
    platform: str = "all",
) -> Dict[str, Any]:
    pend = {r.get("agent"): r for r in pending}
    agents = []
    for key, name, plat in INSTALL_AGENTS:
        if platform not in ("all", plat):
            continue
        agents.append({
            "agent": key,
            "name": name,
            "platform": plat,
            "devices": _int(counts.get(f"{key}_devices")),
            "withErrors": {"count": _int(counts.get(f"{key}_with_errors")),
                           "link": link("/installs", filter="errors", agent=key)},
            "withWarnings": {"count": _int(counts.get(f"{key}_with_warnings")),
                             "link": link("/installs", filter="warnings", agent=key)},
            "errorItems": {"count": _int(counts.get(f"{key}_error_items")),
                           "link": link("/installs", filter="errors", agent=key)},
            "warningItems": {"count": _int(counts.get(f"{key}_warning_items")),
                             "link": link("/installs", filter="warnings", agent=key)},
            "pending": {"items": _int(pend.get(key, {}).get("items")),
                        "devices": _int(pend.get(key, {}).get("devices")),
                        "link": link("/installs", filter="pending", agent=key)},
            "silentAgents": {"count": _int(silent.get(key)),
                             "link": link("/installs", stale=1, agent=key)},
        })

    def total(field: str, sub: str = "count") -> int:
        return sum(a[field][sub] for a in agents)

    return {
        "devices": sum(a["devices"] for a in agents),
        "withErrors": {"count": total("withErrors"), "link": link("/installs", filter="errors")},
        "withWarnings": {"count": total("withWarnings"), "link": link("/installs", filter="warnings")},
        "errorItems": {"count": total("errorItems"), "link": link("/installs", filter="errors")},
        "warningItems": {"count": total("warningItems"), "link": link("/installs", filter="warnings")},
        "pending": {"items": total("pending", "items"), "devices": total("pending", "devices"),
                    "link": link("/installs", filter="pending")},
        "silentAgents": {"count": total("silentAgents"), "thresholdDays": SILENT_AGENT_DAYS,
                         "link": link("/installs", stale=1)},
        "topFailing": [
            {"name": r["name"], "devices": _int(r.get("devices")),
             "link": link("/installs", item=r["name"], filter="errors")}
            for r in failing
        ],
        "byAgent": agents,
    }


def card_install_health(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_install_health(
        run("install_counts")[0],
        run("install_items_failing", limit=TOP_N),
        silent_agent_counts(run("install_agent_runs")),
        run("install_items_pending"),
        scope.platform,
    )


# ── Check-in Gaps ─────────────────────────────────────────────

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


# ── OS Currency ───────────────────────────────────────────────

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


# ── Software Risk ─────────────────────────────────────────────


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


# ── Expiring Certificates ─────────────────────────────────────


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


# ── Directory Services ──────────────────────────────────────────

#: The Identity report Directory Services widget: its categories and labels,
#: in its order, and the trust breakdown of Domain Joined. (key, label, column)
DIRECTORY_SEGMENTS = (
    ("cloud", "Cloud Joined", "cloud_joined"),
    ("domain", "Domain Joined", "domain_joined"),
    ("standard", "Standard", "standard"),
    ("unjoined", "Unjoined", "unjoined"),
)
DIRECTORY_TRUST = (
    ("trusted", "Trusted", "trusted"),
    ("unconfirmed", "Unconfirmed", "unconfirmed"),
    ("broken", "Broken", "broken"),
)


def _scoped(platform: str) -> Optional[str]:
    return None if platform == "all" else platform


def shape_directory_services(row: Dict[str, Any], platform: str = "all") -> Dict[str, Any]:
    p = _scoped(platform)

    def segment(key: str, label: str, col: str) -> Dict[str, Any]:
        return {"key": key, "label": label, "count": _int(row.get(col)),
                "link": link("/identity", directory=key, platform=p)}

    segments = []
    for key, label, col in DIRECTORY_SEGMENTS:
        entry = segment(key, label, col)
        if key == "domain":
            entry["children"] = [segment(k, l, c) for k, l, c in DIRECTORY_TRUST]
        segments.append(entry)
    return {
        "total": _int(row.get("devices")),
        "segments": segments,
        "extraAdmins": {"count": _int(row.get("extra_admins")), "link": link("/identity", admins="extra", platform=p)},
        "shared": {"count": _int(row.get("shared")), "link": link("/identity", usage="shared", platform=p)},
        "assigned": {"count": _int(row.get("assigned")), "link": link("/identity", usage="assigned", platform=p)},
    }


def card_directory_services(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_directory_services(run("directory_services")[0], scope.platform)


# ── Connectivity Problems ────────────────────────────────────


def shape_connectivity(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "devices": _int(row.get("devices")),
        "weakSignal": {
            "count": _int(row.get("weak_signal")),
            "link": link("/network", signal="weak"),
        },
        "poorQuality": {
            "count": _int(row.get("poor_quality")),
            "measured": _int(row.get("quality_measured")),
            "link": link("/network", quality="poor"),
        },
        "onVpn": {"count": _int(row.get("on_vpn")), "link": link("/network", vpn=1)},
    }


def card_connectivity(run: Runner, scope: InsightsScope) -> Dict[str, Any]:
    return shape_connectivity(run("network_problems")[0])


# ── Orchestration ───────────────────────────────────────────────

CARD_FUNCTIONS: Dict[str, Callable[..., Dict[str, Any]]] = {
    "rebootDebt": card_reboot_debt,
    "protectionGaps": card_protection_gaps,
    "managementToolLogs": card_management_tools,
    "storage": card_storage,
    "installHealth": card_install_health,
    "checkinGaps": card_checkin_gaps,
    "osCurrency": card_os_currency,
    "softwareRisk": card_software_risk,
    "expiringCertificates": card_certificates,
    "directoryServices": card_directory_services,
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
    Any failure becomes ``{"error": ...}`` for this card alone. Every result
    carries ``generatedAt``."""
    fn = CARD_FUNCTIONS[key]
    conn = None
    t0 = _time.monotonic()
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        # SET LOCAL lasts until this transaction ends; closing the connection
        # rolls back, so the pooled connection returns with its own timeout.
        cursor.execute(f"SET LOCAL statement_timeout = '{int(STATEMENT_TIMEOUT_SECONDS * 1000)}ms'")
        run = _make_runner(cursor, scope)
        result = fn(run, scope, cursor=cursor) if key == "checkinGaps" else fn(run, scope)
        logger.info(f"[INSIGHTS] {key} platform={scope.platform}: {_time.monotonic() - t0:.3f}s")
    except Exception as exc:
        logger.error(f"[INSIGHTS] {key} platform={scope.platform} failed after {_time.monotonic() - t0:.3f}s: {exc}")
        result = {"error": _error_text(exc)}
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
    result["generatedAt"] = datetime.now(timezone.utc).isoformat()
    result["computeSeconds"] = round(_time.monotonic() - t0, 3)
    return result


_inventory_state_checked: Optional[tuple] = None
_INVENTORY_STATE_RECHECK_SECONDS = 600


def _has_inventory_state_table() -> bool:
    """Whether device_inventory_state exists, rechecked every ten minutes."""
    global _inventory_state_checked
    now = _time.monotonic()
    if _inventory_state_checked and now - _inventory_state_checked[1] < _INVENTORY_STATE_RECHECK_SECONDS:
        return _inventory_state_checked[0]
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT to_regclass('device_inventory_state') IS NOT NULL")
        row = cursor.fetchone()
        found = bool(row and row[0])
        _inventory_state_checked = (found, now)
        return found
    except Exception as exc:
        logger.warning(f"[INSIGHTS] Could not check for device_inventory_state: {exc}")
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def compute_card(key: str, platform: str = "all", include_archived: bool = False) -> Dict[str, Any]:
    """One card for one scope. Synchronous: run it off the event loop."""
    return run_card(key, InsightsScope(platform, include_archived, _has_inventory_state_table()))


def compute_insights(platform: str = "all", include_archived: bool = False) -> Dict[str, Any]:
    """Every card for one scope at once (CONCURRENCY at a time). The endpoint
    assembles the same document from per-card caches instead."""
    t0 = _time.monotonic()
    scope = InsightsScope(platform, include_archived, _has_inventory_state_table())
    with ThreadPoolExecutor(max_workers=CONCURRENCY, thread_name_prefix="insights") as pool:
        futures = {key: pool.submit(run_card, key, scope) for key in CARD_KEYS}
        cards = {key: futures[key].result() for key in CARD_KEYS}
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "platform": platform,
        "includeArchived": include_archived,
        "computeSeconds": round(_time.monotonic() - t0, 3),
        "cards": cards,
    }


# ── App Usage (GET /dashboard/insights/app-usage) ───────────────

APP_USAGE_TOP = 10


def fold_name(raw: str) -> str:
    """The usage bucket a raw app name belongs to (canonicalize_app_name)."""
    name = (raw or "").strip()
    if not name:
        return ""
    return (canonicalize_app_name(name) or name).strip()


def _csv(values: Sequence[str]) -> Optional[str]:
    return ",".join(values) if values else None


def app_usage_link(name: str, days: int = USAGE_DAYS, usages: Sequence[str] = (),
                   catalogs: Sequence[str] = (), platform: str = "all") -> Dict[str, Any]:
    return link(f"/applications/usage/{quote(str(name), safe='')}", days=days,
                usages=_csv(usages), catalogs=_csv(catalogs),
                platform=None if platform == "all" else platform)


def shape_app_usage(usage: Sequence[Dict[str, Any]], options: Sequence[Dict[str, Any]], *,
                    platform: str, days: int, usages: Sequence[str], catalogs: Sequence[str]) -> Dict[str, Any]:
    apps = sorted(
        ({
            "name": r["app"],
            "totalHours": round(float(r.get("total_seconds") or 0) / 3600.0, 1),
            "activeHours": round(float(r.get("active_seconds") or 0) / 3600.0, 1),
            "devices": _int(r.get("device_count")),
            "activeDevices": _int(r.get("active_device_count")),
        } for r in usage),
        key=lambda a: (-a["totalHours"], a["name"]),
    )[:APP_USAGE_TOP]
    for a in apps:
        a["link"] = app_usage_link(a["name"], days, usages, catalogs, platform)
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "platform": platform,
        "days": days,
        "filters": {"usages": list(usages), "catalogs": list(catalogs)},
        "available": {
            "usages": [{"value": o["value"], "devices": _int(o.get("devices"))} for o in options if o.get("kind") == "usage"],
            "catalogs": [{"value": o["value"], "devices": _int(o.get("devices"))} for o in options if o.get("kind") == "catalog"],
        },
        "link": link("/applications", type="usage", period=days, usages=_csv(usages),
                     catalogs=_csv(catalogs), platform=None if platform == "all" else platform),
        "apps": apps,
    }


def _app_usage(run: Runner, scope: InsightsScope, days: int, usages: Sequence[str],
               catalogs: Sequence[str], today: Optional[date] = None) -> Dict[str, Any]:
    cutoff = (today or datetime.now(timezone.utc).date()) - timedelta(days=days)
    lower_u = [u.lower() for u in usages]
    lower_c = [c.lower() for c in catalogs]
    scoped = {"cutoff": cutoff, "usages": lower_u, "catalogs": lower_c}
    options = run("usage_filter_options")
    display: Dict[str, str] = {}
    raw_names, keys = [], []
    for r in run("usage_app_names", **scoped):
        folded = fold_name(r["app_name"])
        if not folded:
            continue
        key = folded.lower()
        display.setdefault(key, folded)
        raw_names.append(r["app_name"])
        keys.append(key)
    usage = run("usage_by_app", raw_names=raw_names, folded_names=keys, **scoped) if raw_names else []
    for r in usage:
        r["app"] = display.get(r["app"], r["app"])
    return shape_app_usage(usage, options, platform=scope.platform, days=days,
                           usages=usages, catalogs=catalogs)


def compute_app_usage(platform: str = "all", usages: Sequence[str] = (), catalogs: Sequence[str] = (),
                      days: int = USAGE_DAYS) -> Dict[str, Any]:
    """The App Usage card: top apps by hours within an inventory scope, and the
    usage and catalog values to filter by. A failure is ``{"error": ...}``."""
    t0 = _time.monotonic()
    scope = InsightsScope(platform, False, _has_inventory_state_table())
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f"SET LOCAL statement_timeout = '{int(STATEMENT_TIMEOUT_SECONDS * 1000)}ms'")
        result = _app_usage(_make_runner(cursor, scope), scope, days, list(usages), list(catalogs))
        logger.info(f"[INSIGHTS] appUsage platform={platform}: {_time.monotonic() - t0:.3f}s")
    except Exception as exc:
        logger.error(f"[INSIGHTS] appUsage platform={platform} failed: {exc}")
        result = {"error": _error_text(exc), "generatedAt": datetime.now(timezone.utc).isoformat()}
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
    result["computeSeconds"] = round(_time.monotonic() - t0, 3)
    return result


# ── Management Tools Logs: matching devices ─────────────────────

TOOL_DEVICES_LIMIT = 5000
TOOL_LEVELS = ("error", "warning")


def shape_tool_devices(rows: Sequence[Dict[str, Any]], *, tool: str, level: str, hours: int,
                       platform: str) -> Dict[str, Any]:
    return {
        "tool": tool,
        "level": level,
        "hours": hours,
        "platform": platform,
        "devices": [
            {
                "serialNumber": r["serial"],
                "deviceName": r.get("name") or r["serial"],
                "platform": r.get("platform"),
                "count": _int(r.get("lines")),
                "lastAt": f"{r['last_hour']}:00:00Z" if r.get("last_hour") else None,
                "link": tool_device_link(r["serial"], tool, level),
            }
            for r in rows
        ],
    }


def compute_tool_devices(tool: str, level: str = "error", hours: int = TOOL_WINDOW_HOURS,
                         platform: str = "all") -> Dict[str, Any]:
    """Devices with ``level`` lines in ``tool``'s log in the last ``hours``,
    most lines first. ``lastAt`` is the start of the latest UTC hour with one.
    A failure is ``{"error": ...}``."""
    t0 = _time.monotonic()
    scope = InsightsScope(platform, False, _has_inventory_state_table())
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(f"SET LOCAL statement_timeout = '{int(STATEMENT_TIMEOUT_SECONDS * 1000)}ms'")
        rows = _make_runner(cursor, scope)(
            "management_tool_devices", tool=tool.lower(), slot=TOOL_LEVELS.index(level),
            since_hour=window_start_hour(hours=hours), limit=TOOL_DEVICES_LIMIT,
        )
        result = shape_tool_devices(rows, tool=tool.lower(), level=level, hours=hours, platform=platform)
        logger.info(f"[INSIGHTS] tool devices {tool}/{level}/{hours}h platform={platform}: "
                    f"{len(rows)} devices, {_time.monotonic() - t0:.3f}s")
    except Exception as exc:
        logger.error(f"[INSIGHTS] tool devices {tool}/{level} failed: {exc}")
        result = {"tool": tool.lower(), "level": level, "hours": hours, "platform": platform,
                  "error": _error_text(exc)}
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
    result["generatedAt"] = datetime.now(timezone.utc).isoformat()
    return result
