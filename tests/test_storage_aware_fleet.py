"""Fleet reports treat a stored device as Storage, not as a fault.

An asset inventory can report a device as checked in to a storage room. Such a
device is expected to be silent, so the per-device fleet endpoints carry its
inventory state for the pages to read, and the endpoints that judge devices
server-side -- stale agents, usage collection health -- count it apart.

The database is mocked (CI has none).
"""

from datetime import datetime, timedelta, timezone

from routers import fleet

STORED = {"state": "storage", "storageLocation": "Room 9", "leaseNumber": None,
          "assetTag": None, "updatedAt": None}
OUT = {"state": "checked_out", "storageLocation": None, "leaseNumber": None,
       "assetTag": None, "updatedAt": None}


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def execute(self, sql, params=None):
        pass

    def fetchall(self):
        return self.rows


class FakeConn:
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return FakeCursor(self.rows)

    def close(self):
        pass


def _no_cache(monkeypatch):
    monkeypatch.setattr(fleet, "cache_get", lambda *a, **k: None)
    monkeypatch.setattr(fleet, "cache_set", lambda *a, **k: None)


def test_attach_puts_state_on_matching_rows_by_upper_cased_serial():
    rows = [{"serialNumber": "serial-a"}, {"serialNumber": "SERIAL-B"}, {"serialNumber": None}]
    fleet.attach_inventory_states(rows, {"SERIAL-A": STORED})
    assert rows[0]["inventoryState"] == STORED
    assert "inventoryState" not in rows[1]
    assert "inventoryState" not in rows[2]


def test_state_is_read_on_the_endpoint_connection(monkeypatch):
    """One connection per uncached request: the overlay rides the query's own."""
    _no_cache(monkeypatch)
    opened = []

    def connect():
        opened.append(1)
        return FakeConn([])

    seen = []
    monkeypatch.setattr(fleet, "get_db_connection", connect)
    monkeypatch.setattr(fleet, "load_sql", lambda name: "SELECT 1")
    monkeypatch.setattr(fleet, "fetch_inventory_states", lambda conn: seen.append(conn) or {})

    fleet.get_installs_filters(include_archived=False)

    assert len(opened) == 1
    assert len(seen) == 1


def test_attach_with_no_states_leaves_rows_untouched():
    rows = [{"serialNumber": "SERIAL-A"}]
    assert fleet.attach_inventory_states(rows, {}) == [{"serialNumber": "SERIAL-A"}]


def _installs_row(serial, last_seen, last_run):
    installs = {"cimian": {"version": "1", "items": [],
                           "sessions": [{"endTime": last_run.isoformat()}]}}
    return (serial, serial, "Assigned", "Production", "Room", None, "Dept",
            None, "Windows NT", installs, last_seen)


def test_stored_device_is_not_a_stale_agent(monkeypatch):
    _no_cache(monkeypatch)
    now = datetime.now(timezone.utc)
    rows = [
        _installs_row("SERIAL-STORED", now, now - timedelta(days=10)),
        _installs_row("SERIAL-INUSE", now, now - timedelta(days=10)),
    ]
    monkeypatch.setattr(fleet, "get_db_connection", lambda: FakeConn(rows))
    monkeypatch.setattr(fleet, "load_sql", lambda name: "SELECT 1")
    monkeypatch.setattr(fleet, "fetch_inventory_states",
                        lambda conn: {"SERIAL-STORED": STORED, "SERIAL-INUSE": OUT})

    result = fleet.get_installs_filters(include_archived=False)

    assert [a["serialNumber"] for a in result["staleAgents"]] == ["SERIAL-INUSE"]
    assert result["storageDeviceCount"] == 1
    by_serial = {d["serialNumber"]: d for d in result["devices"]}
    assert by_serial["SERIAL-STORED"]["inventoryState"]["state"] == "storage"


def _health_row(serial, last_usage):
    return (serial, serial, "Windows NT", "Windows", None, "Assigned",
            "Production", "Room", last_usage, 0, 0.0)


def test_collection_health_counts_stored_devices_apart(monkeypatch):
    _no_cache(monkeypatch)
    rows = [_health_row("SERIAL-STORED", None), _health_row("SERIAL-NEVER", None)]
    monkeypatch.setattr(fleet, "get_db_connection", lambda: FakeConn(rows))
    monkeypatch.setattr(fleet, "fetch_inventory_states", lambda conn: {"SERIAL-STORED": STORED})

    result = fleet.get_applications_collection_health(
        request=None, freshDays=7, staleDays=30, include_archived=False
    )

    summary = result["summary"]
    assert summary["storage"] == 1
    assert summary["never"] == 1
    assert summary["totalDevices"] == 1
    assert [d["serialNumber"] for d in result["darkDevices"]] == ["SERIAL-NEVER"]
