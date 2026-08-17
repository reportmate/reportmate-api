"""Which usage_history user entries name a person.

The Security Log path records the subject of event 4688 -- the account that
created the process -- so anything launched by a service, a scheduled task or
the machine itself is attributed to DOMAIN\\COMPUTER$ rather than the person at
the keyboard. Measured over a 2-day fleet window, 253 of 513 principals were
computer accounts and the three heaviest "users" of software on campus were
machines.

These cases pin the boundary: what is unambiguously not a person, and -- just
as important -- what must keep counting as one. Over-filtering here silently
deletes real people from the licence evidence, which is the failure mode that
costs more than the one being fixed. Work item 4522.
"""

import pytest

from routers.fleet import is_human_principal


@pytest.mark.parametrize("name", [
    "ECUAD\\jsmith12345",
    "ECUAD\\mgarciasantos",
    "ECUAD\\akowalskilopez",
    "student",                      # shared local account, still a login
    "EDIT-02\\dl-worker",      # service account, but a policy call not a
                                    # detectable one -- see work item 4261
    "ECUAD\\release",
    "WORKGROUP\\someone",
    "a",
])
def test_people_are_kept(name):
    assert is_human_principal(name) is True


@pytest.mark.parametrize("name", [
    "ECUAD\\LAB-A-04-1$",
    "WORKGROUP\\STD-16$",
    "WORKGROUP\\EDIT-02$",
    "WORKGROUP\\REMOTE-26$",
    "EXAMPLEHOST$",                # machine account with no domain prefix
    "EXAMPLE-HOST-2$",
])
def test_computer_accounts_are_excluded(name):
    assert is_human_principal(name) is False


@pytest.mark.parametrize("name", [
    "NT AUTHORITY\\LOCAL SERVICE",
    "NT AUTHORITY\\SYSTEM",
    "NT AUTHORITY\\NETWORK SERVICE",
    "nt authority\\system",
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "TrustedInstaller",
])
def test_service_principals_are_excluded(name):
    assert is_human_principal(name) is False


@pytest.mark.parametrize("name", [None, "", "   ", "\t"])
def test_empty_is_not_a_person(name):
    assert is_human_principal(name) is False


def test_surrounding_whitespace_does_not_defeat_the_rule():
    # usage_history users come from a JSONB array assembled on the client, so
    # padding survives to here. A padded machine account is still a machine.
    assert is_human_principal("  ECUAD\\LAB-A-04-1$  ") is False
    assert is_human_principal("  NT AUTHORITY\\SYSTEM  ") is False
    assert is_human_principal("  ECUAD\\jsmith12345  ") is True


def test_dollar_inside_the_name_is_not_a_computer_account():
    # Only a trailing $ marks a computer account. A name that merely contains
    # one is a person with an awkward username.
    assert is_human_principal("ECUAD\\ke$ha") is True
