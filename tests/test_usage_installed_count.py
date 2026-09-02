"""installedDeviceCount on /applications/usage comes from the applications
inventory, folded by the same alias rules as the usage buckets, so the
install denominator and the active numerator land on the same row."""
from routers.fleet import fold_installed_devices


def test_fleet_wide_fold_uses_alias_map_and_dedupes_devices():
    rows = [
        ("Adobe Illustrator 2025", ["A", "B"]),
        ("Adobe Illustrator 2024", ["B", "C"]),
        ("Adobe Acrobat (64-bit)", ["A"]),
        ("Acrobat", ["D"]),
        ("Google Chrome", ["A", "B", "C", "D"]),
        ("", ["Z"]),
        (None, ["Z"]),
    ]
    folded = fold_installed_devices(rows, {})
    assert folded["adobe illustrator"] == {"A", "B", "C"}
    assert folded["adobe acrobat"] == {"A", "D"}
    assert folded["google chrome"] == {"A", "B", "C", "D"}
    assert "" not in folded


def test_mac_bundle_suffix_is_stripped_before_folding():
    rows = [
        ("Microsoft Outlook.app", ["A"]),
        ("Safari.app", ["A", "B"]),
        ("Google Chrome.app", ["A"]),
        ("Google Chrome Helper.app", ["A"]),
        ("Microsoft Outlook", ["C"]),
        (".app", ["Z"]),
    ]
    folded = fold_installed_devices(rows, {})
    assert folded["microsoft outlook"] == {"A", "C"}
    assert folded["safari"] == {"A", "B"}
    assert folded["google chrome"] == {"A"}
    assert "" not in folded


def test_explicit_pick_matches_exact_name_only():
    rows = [
        ("Final Cut Pro", ["A"]),
        ("final cut pro", ["B"]),
        ("Final Cut Pro Creator Studio", ["C"]),
        ("Final Cut Pro.app", ["D"]),
    ]
    folded = fold_installed_devices(rows, {"final cut pro": "Final Cut Pro"})
    assert folded == {"final cut pro": {"A", "B", "D"}}


def test_no_rows_gives_empty_map():
    assert fold_installed_devices([], {}) == {}
