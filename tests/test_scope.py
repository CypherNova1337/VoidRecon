from voidrecon.core.models import ScopeState
from voidrecon.core.scope import Scope, ScopeRule


def test_apex_covers_subdomains_by_default():
    scope = Scope.from_lists(["example.com"])
    assert scope.classify_host("example.com") == ScopeState.IN_SCOPE
    assert scope.classify_host("dev.example.com") == ScopeState.IN_SCOPE
    assert scope.classify_host("other.com") == ScopeState.UNKNOWN


def test_wildcard_apex_disabled_restricts_to_apex():
    scope = Scope.from_lists(["example.com"], wildcard_apex=False)
    assert scope.classify_host("example.com") == ScopeState.IN_SCOPE
    assert scope.classify_host("dev.example.com") == ScopeState.UNKNOWN


def test_exclusion_wins():
    scope = Scope.from_lists(["*.example.com"], ["secret.example.com"])
    assert scope.classify_host("secret.example.com") == ScopeState.OUT_OF_SCOPE
    assert scope.classify_host("app.example.com") == ScopeState.IN_SCOPE


def test_explicit_host_rule():
    scope = Scope.from_lists(["app.example.com"], wildcard_apex=True)
    # An explicit non-apex host does not pull in siblings.
    assert scope.classify_host("app.example.com") == ScopeState.IN_SCOPE
    assert scope.classify_host("other.example.com") == ScopeState.UNKNOWN


def test_cidr_and_ip():
    scope = Scope.from_lists(["10.0.0.0/24", "8.8.8.8"])
    assert scope.classify_ip("10.0.0.5") == ScopeState.IN_SCOPE
    assert scope.classify_ip("8.8.8.8") == ScopeState.IN_SCOPE
    assert scope.classify_ip("9.9.9.9") == ScopeState.UNKNOWN


def test_allows_active_only_in_scope():
    scope = Scope.from_lists(["*.example.com"], ["no.example.com"])
    assert scope.allows_active("yes.example.com")
    assert not scope.allows_active("no.example.com")
    assert not scope.allows_active("unknown.org")


def test_is_related_to_seed():
    scope = Scope.from_lists(["example.com"])
    assert scope.is_related("new.example.com")
    assert not scope.is_related("elsewhere.net")


def test_scope_rule_parse_url_extracts_host():
    rule = ScopeRule.parse("https://api.example.com/v1")
    assert rule is not None
    assert rule.value == "api.example.com"
