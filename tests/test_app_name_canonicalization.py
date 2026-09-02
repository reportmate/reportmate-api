"""
Canonical app-name rollup for fleet utilization.

The rule these pin: a vendor's *product* folds its version-suffixed editions
into one row, but the vendor's launcher, updater or embedded runtime is a
different product and keeps its own row. Folding one in makes the product's
row a sum of two different things, and the launcher is the one that runs at
every logon, so it dominates the result.
"""

import pytest

from dependencies import canonicalize_app_name


class TestProductEditionsFold:
    """Version-suffixed editions of one product are one row. This is the
    behaviour the alias map exists for and must not regress."""

    @pytest.mark.parametrize(
        "raw",
        [
            "Houdini 19.5.303",
            "Houdini 20.5.278",
            "Houdini 21.0.440",
            "Houdini 22.0.368",
            "hindie",
            "hython",
        ],
    )
    def test_houdini_editions_fold_to_houdini(self, raw):
        assert canonicalize_app_name(raw) == "Houdini"

    @pytest.mark.parametrize(
        "raw", ["Autodesk Maya 2022", "Autodesk Maya 2024", "Autodesk Maya 2020"]
    )
    def test_maya_editions_fold_to_maya(self, raw):
        assert canonicalize_app_name(raw) == "Maya"


class TestLaunchersStaySeparate:
    def test_houdini_launcher_is_not_houdini(self):
        # Folded in, the launcher supplied roughly 70% of the combined row's
        # hours, over 80% of its launches, and all but a handful of its unique
        # users -- a row reading "many users, almost no use".
        assert canonicalize_app_name("Houdini Launcher") == "Houdini Launcher"

    def test_launcher_rule_precedes_the_general_houdini_rule(self):
        # Order matters in the alias map: a general \bhoudini\b rule placed
        # first would swallow the launcher before its own rule was reached.
        # This is the regression that produced the inflated Houdini row.
        assert canonicalize_app_name("Houdini Launcher") != canonicalize_app_name(
            "Houdini 21.0.440"
        )

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Deadline Launcher", "Deadline Launcher"),
            ("Deadline Worker", "Deadline Worker"),
            ("Deadline Monitor", "Deadline Monitor"),
            ("Unity Hub", "Unity Hub"),
        ],
    )
    def test_existing_launcher_separations_are_preserved(self, raw, expected):
        # These already behaved correctly and are the precedent the Houdini
        # rule now follows.
        assert canonicalize_app_name(raw) == expected

    def test_deadline_launcher_is_not_deadline(self):
        assert canonicalize_app_name("Deadline Launcher") != canonicalize_app_name(
            "Deadline"
        )


class TestEmbeddedRuntimesStaySeparate:
    def test_webview2_is_not_edge(self):
        # WebView2 is the control other applications host to render HTML, not
        # the browser. Folded in, it supplied roughly a third of the browser
        # row's hours and a large majority of its unique users.
        # normalize_app_name() strips "WebView2 Runtime", so only an explicit
        # alias rule keeps them apart.
        assert (
            canonicalize_app_name("Microsoft Edge WebView2 Runtime")
            == "Microsoft Edge WebView2 Runtime"
        )
        assert canonicalize_app_name("Microsoft Edge") == "Microsoft Edge"
        assert canonicalize_app_name(
            "Microsoft Edge WebView2 Runtime"
        ) != canonicalize_app_name("Microsoft Edge")


class TestDistinctProductsNeverMix:
    def test_motion_and_motionbuilder_stay_apart(self):
        # The guarantee that made exact-match attractive in the per-device
        # drill-down, now provided by canonicalization instead.
        assert canonicalize_app_name("MotionBuilder") != canonicalize_app_name("Motion")

    def test_substance_products_stay_apart(self):
        assert canonicalize_app_name("Substance 3D Painter") == "Substance 3D Painter"
        assert canonicalize_app_name("Substance 3D Designer") == "Substance 3D Designer"


class TestCrossPlatformNamesFold:
    """The same product registers under different names per platform; both
    fold to one row, but only on an exact whole-name match."""

    @pytest.mark.parametrize("raw", ["Acrobat", "Adobe Acrobat", "Adobe Acrobat (64-bit)"])
    def test_acrobat_names_fold_to_adobe_acrobat(self, raw):
        assert canonicalize_app_name(raw) == "Adobe Acrobat"

    @pytest.mark.parametrize("raw", ["Microsoft Outlook", "Outlook for Windows", "OUTLOOK"])
    def test_outlook_names_fold_to_microsoft_outlook(self, raw):
        assert canonicalize_app_name(raw) == "Microsoft Outlook"

    @pytest.mark.parametrize(
        "raw",
        [
            "Acrobat Notification Client",
            "Acrobat NUL Self-Manage",
            "Acrobat-SDL",
            "Adobe Acrobat Reader",
            "Zoom Outlook Plugin",
        ],
    )
    def test_adjacent_products_are_not_swallowed(self, raw):
        assert canonicalize_app_name(raw) not in ("Adobe Acrobat", "Microsoft Outlook")


class TestDegenerateInput:
    @pytest.mark.parametrize("raw", ["", "   ", None, 123])
    def test_empty_and_non_string_input_is_empty(self, raw):
        assert canonicalize_app_name(raw) == ""

    def test_unknown_name_is_returned_unchanged(self):
        assert canonicalize_app_name("Some Bespoke Internal Tool") == (
            "Some Bespoke Internal Tool"
        )
