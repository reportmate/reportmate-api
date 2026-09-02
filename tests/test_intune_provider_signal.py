from routers.fleet import _management_reports_intune


def test_mdm_log_root_named_intune_is_an_intune_signal():
    management = {"logs": {"platform": "Windows", "roots": [
        {"tool": "mdm", "name": "Intune", "path": "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs"},
        {"tool": "installs", "name": "Managed Installs", "path": "C:\\ProgramData\\ManagedInstalls\\logs"},
    ]}}
    assert _management_reports_intune(management) is True


def test_other_mdm_root_is_not_an_intune_signal():
    management = {"logs": {"roots": [{"tool": "mdm", "name": "Jamf", "path": "/var/log"}]}}
    assert _management_reports_intune(management) is False


def test_legacy_intune_keys_still_count():
    assert _management_reports_intune({"intunePolicies": [{"id": 1}]}) is True
    assert _management_reports_intune({"recentIntuneLogs": {"entries": [1]}}) is True


def test_empty_or_malformed_management_is_not_intune():
    assert _management_reports_intune(None) is False
    assert _management_reports_intune({}) is False
    assert _management_reports_intune({"logs": "nope"}) is False
    assert _management_reports_intune({"logs": {"roots": [None, "x", {"tool": "installer"}]}}) is False
