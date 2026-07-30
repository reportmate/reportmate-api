"""Passphrase rotation: REPORTMATE_PASSPHRASE is a comma-separated list.

Rotating the shared client credential used to require a flag day, because the
value was compared with a single hmac.compare_digest. Accepting a list lets the
replacement be published alongside the incumbent, shipped to the fleet, and the
incumbent dropped only once every client has moved.

Fixture values below are deliberately meaningless tokens ("token-a"), not
credential-shaped strings, so secret scanners have nothing to flag.
"""

import hmac

from dependencies import _parse_passphrases

CURRENT = "token-a"
DEPRECATED = "token-b"
CONFIGURED = f"{CURRENT},{DEPRECATED}"


def _matches(presented: str, configured: str) -> int:
    """Mirror of the auth path's comparison, returning the matched position."""
    matched = -1
    for idx, candidate in enumerate(_parse_passphrases(configured)):
        if hmac.compare_digest(presented, candidate):
            matched = idx
    return matched


class TestParsing:
    def test_single_value_is_one_entry(self):
        assert _parse_passphrases(CURRENT) == [CURRENT]

    def test_splits_on_comma(self):
        assert _parse_passphrases(CONFIGURED) == [CURRENT, DEPRECATED]

    def test_strips_surrounding_whitespace(self):
        # A human editing a variable group will leave spaces after the comma.
        assert _parse_passphrases(f" {CURRENT} , {DEPRECATED} ") == [CURRENT, DEPRECATED]

    def test_drops_empty_entries(self):
        # Trailing comma, or an entry cleared to "" partway through a rotation.
        assert _parse_passphrases(f"{CURRENT},,{DEPRECATED},") == [CURRENT, DEPRECATED]

    def test_unset_is_empty(self):
        assert _parse_passphrases(None) == []
        assert _parse_passphrases("") == []
        assert _parse_passphrases("   ") == []


class TestRotationWindow:
    def test_current_value_authenticates_at_position_zero(self):
        assert _matches(CURRENT, CONFIGURED) == 0

    def test_deprecated_value_still_authenticates(self):
        # The point of the overlap window: a client that has not yet received
        # the new package keeps reporting.
        assert _matches(DEPRECATED, CONFIGURED) == 1

    def test_unknown_value_is_rejected(self):
        assert _matches("token-z", CONFIGURED) == -1

    def test_concatenation_is_not_itself_valid(self):
        # The regression this replaces: with a single compare, the joined
        # string was the only accepted value, so both real entries failed.
        assert _matches(CONFIGURED, CONFIGURED) == -1

    def test_after_retiring_the_deprecated_entry_it_stops_working(self):
        assert _matches(DEPRECATED, CURRENT) == -1
        assert _matches(CURRENT, CURRENT) == 0

    def test_nothing_authenticates_when_unset(self):
        assert _matches(CURRENT, "") == -1

    def test_empty_presented_value_never_matches(self):
        # Guards against a client sending an unresolved ${REPORTMATE_PASSPHRASE}
        # placeholder that collapsed to empty.
        assert _matches("", CONFIGURED) == -1


class TestRuntimeReconfiguration:
    """The list is parsed per request, not once at import.

    An earlier version of this change cached the parsed list at import time,
    which silently broke every caller that sets REPORTMATE_PASSPHRASE at
    runtime -- including the existing auth tests, which monkeypatch the module
    attribute. CI caught it; this pins the behaviour.
    """

    def test_setting_the_attribute_takes_effect(self, monkeypatch):
        import dependencies

        monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", CURRENT)
        assert _parse_passphrases(dependencies.REPORTMATE_PASSPHRASE) == [CURRENT]

        monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", CONFIGURED)
        assert _parse_passphrases(dependencies.REPORTMATE_PASSPHRASE) == [
            CURRENT,
            DEPRECATED,
        ]

    def test_a_single_value_still_behaves_as_before(self, monkeypatch):
        # Backwards compatibility: the overwhelmingly common configuration is
        # one passphrase with no comma, and it must keep working untouched.
        import dependencies

        monkeypatch.setattr(dependencies, "REPORTMATE_PASSPHRASE", CURRENT)
        assert _matches(CURRENT, dependencies.REPORTMATE_PASSPHRASE) == 0
        assert _matches(DEPRECATED, dependencies.REPORTMATE_PASSPHRASE) == -1
