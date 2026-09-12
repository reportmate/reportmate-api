"""Deleting a device must take its module rows with it.

The module tables are created by the ingestion path rather than by a migration,
and none of them declares a foreign key to devices, so nothing cascades. The
endpoint nevertheless described itself as relying on one, deleted only the
devices row, and reported the module rows it had merely counted as deleted --
which is where the orphans /admin/orphans finds came from.

These read the source rather than exercising the database, because the failure
was a missing statement, not wrong SQL: the delete has to name every module
table and the events table explicitly.
"""
import re
from pathlib import Path

SOURCE = (Path(__file__).resolve().parent.parent / "routers" / "admin.py").read_text()


def _delete_device_body() -> str:
    start = SOURCE.index("def delete_device(")
    end = SOURCE.index("@router.get(", start)
    return SOURCE[start:end]


def test_every_module_table_is_deleted_explicitly():
    body = _delete_device_body()
    assert re.search(r"for table in _MODULE_TABLES:", body), \
        "delete_device must iterate the module tables"
    assert re.search(r"DELETE FROM \{table\} WHERE device_id = %s", body), \
        "delete_device must delete each module table's rows for the device"


def test_events_are_deleted_explicitly():
    assert 'DELETE FROM events WHERE device_id = %s' in _delete_device_body()


def test_usage_history_is_still_deleted():
    assert "DELETE FROM usage_history WHERE device_id = %s" in _delete_device_body()


def test_the_response_reports_what_was_deleted_not_what_was_counted():
    body = _delete_device_body()
    # module_rows_deleted is the running total of rows the deletes actually
    # removed; module_counts is the pre-delete survey used only for logging.
    assert '"totalModuleRecords": module_rows_deleted' in body
    assert '"events": events_deleted' in body


def test_no_claim_of_a_cascade_survives():
    body = _delete_device_body()
    assert "CASCADE will delete" not in body
    assert "cascading delete via foreign keys" not in body
