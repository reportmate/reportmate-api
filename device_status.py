"""One definition of a device's connection status: online, idle or offline.

Status is derived from ``last_seen`` at read time, never stored. The
``devices.status`` column is written once, as ``'online'``, when ingest first
creates the row, and nothing updates it afterwards, so a device that stopped
reporting weeks ago still carried the status it had the day it enrolled. The
dashboard already derived status from ``last_seen``; the device list and detail
endpoints returned the stored column, so the two disagreed about the same
device. Every endpoint now asks this module, so they cannot drift again.

Thresholds:

- ``online``  -- reported within the last hour.
- ``idle``    -- last report more than an hour ago, within a day.
- ``offline`` -- last report more than a day ago.

A device with no ``last_seen`` reads ``online``, matching the dashboard's
historical behaviour; ingest always sets ``last_seen`` when it creates a row.
"""

from datetime import datetime, timezone
from typing import Optional

IDLE_AFTER_SECONDS = 3600
OFFLINE_AFTER_SECONDS = 86400


def derive_device_status(
    last_seen: Optional[datetime], now: Optional[datetime] = None
) -> str:
    """Return ``online``, ``idle`` or ``offline`` for a device's ``last_seen``.

    A naive ``last_seen`` is treated as UTC, which is how the column is written.
    """
    if not last_seen:
        return "online"
    if now is None:
        now = datetime.now(timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age_seconds = (now - last_seen).total_seconds()
    if age_seconds > OFFLINE_AFTER_SECONDS:
        return "offline"
    if age_seconds > IDLE_AFTER_SECONDS:
        return "idle"
    return "online"
