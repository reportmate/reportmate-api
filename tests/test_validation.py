"""Ingestion payload validation (EventSubmission / EventMetadata).

These lock in the envelope contract for POST /api/v1/events: required device
identifiers, enum-constrained platform/collectionType, and the deliberate
``extra="allow"`` that lets module bodies ride as top-level keys.
"""

import pytest
from pydantic import ValidationError
from dependencies import EventSubmission


def _meta(**over):
    base = {"deviceId": "uuid-1", "serialNumber": "ABC123"}
    base.update(over)
    return base


def test_valid_minimal_submission():
    sub = EventSubmission.model_validate({"metadata": _meta()})
    assert sub.metadata.serialNumber == "ABC123"
    assert sub.metadata.platform == "Unknown"  # default
    assert sub.metadata.collectionType == "Full"  # default


def test_missing_serial_number_rejected():
    with pytest.raises(ValidationError):
        EventSubmission.model_validate({"metadata": {"deviceId": "uuid-1"}})


def test_missing_device_id_rejected():
    with pytest.raises(ValidationError):
        EventSubmission.model_validate({"metadata": {"serialNumber": "ABC123"}})


def test_empty_serial_number_rejected():
    with pytest.raises(ValidationError):
        EventSubmission.model_validate({"metadata": _meta(serialNumber="")})


def test_invalid_platform_rejected():
    with pytest.raises(ValidationError):
        EventSubmission.model_validate({"metadata": _meta(platform="BeOS")})


def test_invalid_collection_type_rejected():
    with pytest.raises(ValidationError):
        EventSubmission.model_validate({"metadata": _meta(collectionType="Partial")})


@pytest.mark.parametrize("platform", ["Windows", "macOS", "Linux", "Unknown"])
def test_valid_platforms_accepted(platform):
    sub = EventSubmission.model_validate({"metadata": _meta(platform=platform)})
    assert sub.metadata.platform == platform


def test_extra_top_level_module_keys_allowed():
    # Module bodies arrive as top-level keys (system, hardware, ...) by design.
    payload = {"metadata": _meta(), "hardware": {"cpu": "M1"}, "system": {"os": "x"}}
    sub = EventSubmission.model_validate(payload)
    assert sub.metadata.serialNumber == "ABC123"


def test_missing_metadata_rejected():
    with pytest.raises(ValidationError):
        EventSubmission.model_validate({"hardware": {"cpu": "M1"}})
