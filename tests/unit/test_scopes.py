"""Unit tests for agcms.common.scopes and gateway scope enforcement."""
from __future__ import annotations

import pytest

from agcms.common import scopes


class TestScopesForRole:
    def test_admin_has_all(self):
        assert scopes.scopes_for_role("admin") == scopes.ALL_SCOPES

    def test_compliance_has_read_plus_ingest(self):
        s = scopes.scopes_for_role("compliance")
        assert scopes.READ_AUDIT in s
        assert scopes.READ_POLICY in s
        assert scopes.INGEST in s
        assert scopes.WRITE_POLICY not in s
        assert scopes.ADMIN not in s

    def test_user_is_ingest_only(self):
        assert scopes.scopes_for_role("user") == frozenset({scopes.INGEST})

    def test_unknown_role_is_ingest_only(self):
        # Must NOT fall through to admin — typos can't escalate privilege.
        assert scopes.scopes_for_role("superduper") == frozenset({scopes.INGEST})


class TestHasScope:
    def test_direct_grant(self):
        assert scopes.has_scope({scopes.READ_AUDIT}, scopes.READ_AUDIT)

    def test_admin_satisfies_any(self):
        # Being admin means "has every other scope implicitly"
        assert scopes.has_scope({scopes.ADMIN}, scopes.WRITE_POLICY)
        assert scopes.has_scope({scopes.ADMIN}, scopes.READ_AUDIT)
        assert scopes.has_scope({scopes.ADMIN}, scopes.INGEST)

    def test_missing_scope_rejected(self):
        assert not scopes.has_scope({scopes.INGEST}, scopes.WRITE_POLICY)

    def test_empty_grants_nothing(self):
        assert not scopes.has_scope(set(), scopes.INGEST)


class TestValidateScopes:
    def test_returns_deduped_sorted(self):
        assert scopes.validate_scopes(
            [scopes.READ_POLICY, scopes.INGEST, scopes.INGEST]
        ) == [scopes.INGEST, scopes.READ_POLICY]

    def test_unknown_scope_raises(self):
        with pytest.raises(ValueError, match="Unknown scope"):
            scopes.validate_scopes([scopes.INGEST, "delete:everything"])

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="At least one scope"):
            scopes.validate_scopes([])
