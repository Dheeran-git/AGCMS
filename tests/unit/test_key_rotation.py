"""Unit tests for the signing-key rotation state machine."""
from __future__ import annotations

import hashlib

import pytest

from agcms.audit.key_rotation import (
    Rotation,
    RotationError,
    RotationState,
    approve,
    cancel,
    execute,
    hash_key_material,
    propose,
)


def _fresh_proposal(**overrides) -> Rotation:
    defaults = dict(
        purpose="row",
        new_kid="v2",
        new_key_material=b"x" * 32,
        old_kid="v1",
        proposed_by="alice",
        reason="quarterly rotation per SOC 2 control CC6.1",
        existing_kids=["v0", "v1", "a1"],
    )
    defaults.update(overrides)
    return propose(**defaults)


class TestHashKeyMaterial:
    def test_hashes_bytes(self):
        assert hash_key_material(b"hello") == hashlib.sha256(b"hello").hexdigest()

    def test_hashes_strings(self):
        assert hash_key_material("hello") == hashlib.sha256(b"hello").hexdigest()

    def test_empty_material_rejected(self):
        with pytest.raises(RotationError, match="empty"):
            hash_key_material(b"")


class TestPropose:
    def test_happy_path(self):
        r = _fresh_proposal()
        assert r.state is RotationState.PROPOSED
        assert r.purpose == "row"
        assert r.new_kid == "v2"
        assert r.old_kid == "v1"
        assert r.proposed_by == "alice"
        assert r.new_key_hash == hashlib.sha256(b"x" * 32).hexdigest()
        assert r.approved_by is None
        assert r.executed_by is None

    def test_unknown_purpose_rejected(self):
        with pytest.raises(RotationError, match="purpose"):
            _fresh_proposal(purpose="totally-bogus")

    def test_blank_new_kid_rejected(self):
        with pytest.raises(RotationError, match="new_kid"):
            _fresh_proposal(new_kid="   ")

    def test_new_kid_same_as_old_kid_rejected(self):
        with pytest.raises(RotationError, match="differ"):
            _fresh_proposal(new_kid="v1")

    def test_new_kid_collision_rejected(self):
        with pytest.raises(RotationError, match="already exists"):
            _fresh_proposal(new_kid="v0")  # present in existing_kids

    def test_blank_proposer_rejected(self):
        with pytest.raises(RotationError, match="proposed_by"):
            _fresh_proposal(proposed_by="")

    def test_blank_reason_rejected(self):
        with pytest.raises(RotationError, match="reason"):
            _fresh_proposal(reason="")

    def test_anchor_purpose_allowed(self):
        r = _fresh_proposal(purpose="anchor", new_kid="a2", old_kid="a1")
        assert r.purpose == "anchor"


class TestApprove:
    def test_two_person_rule_enforced(self):
        r = _fresh_proposal()  # proposed_by=alice
        with pytest.raises(RotationError, match="two-person"):
            approve(r, approver="alice")

    def test_happy_path(self):
        r = _fresh_proposal()
        approved = approve(r, approver="bob")
        assert approved.state is RotationState.APPROVED
        assert approved.approved_by == "bob"
        assert approved.proposed_by == "alice"

    def test_cannot_approve_already_approved(self):
        r = approve(_fresh_proposal(), approver="bob")
        with pytest.raises(RotationError, match="state 'approved'"):
            approve(r, approver="carol")

    def test_cannot_approve_executed(self):
        r = execute(approve(_fresh_proposal(), approver="bob"), executor="bob")
        with pytest.raises(RotationError):
            approve(r, approver="carol")

    def test_cannot_approve_cancelled(self):
        r = cancel(_fresh_proposal(), canceller="alice")
        with pytest.raises(RotationError):
            approve(r, approver="bob")

    def test_blank_approver_rejected(self):
        r = _fresh_proposal()
        with pytest.raises(RotationError, match="approver"):
            approve(r, approver="")


class TestExecute:
    def test_requires_approved_state(self):
        r = _fresh_proposal()
        with pytest.raises(RotationError, match="state 'proposed'"):
            execute(r, executor="bob")

    def test_happy_path(self):
        r = approve(_fresh_proposal(), approver="bob")
        executed = execute(r, executor="bob")
        assert executed.state is RotationState.EXECUTED
        assert executed.executed_by == "bob"
        assert executed.approved_by == "bob"
        assert executed.proposed_by == "alice"

    def test_cannot_execute_twice(self):
        r = execute(approve(_fresh_proposal(), approver="bob"), executor="bob")
        with pytest.raises(RotationError, match="state 'executed'"):
            execute(r, executor="bob")

    def test_executor_may_be_proposer(self):
        # The operator who updated the env is often the proposer.
        r = execute(approve(_fresh_proposal(), approver="bob"), executor="alice")
        assert r.executed_by == "alice"


class TestCancel:
    def test_cancel_proposed(self):
        r = cancel(_fresh_proposal(), canceller="alice")
        assert r.state is RotationState.CANCELLED
        assert r.cancelled_by == "alice"

    def test_cancel_approved(self):
        r = approve(_fresh_proposal(), approver="bob")
        cancelled = cancel(r, canceller="bob")
        assert cancelled.state is RotationState.CANCELLED

    def test_cannot_cancel_executed(self):
        r = execute(approve(_fresh_proposal(), approver="bob"), executor="bob")
        with pytest.raises(RotationError, match="state 'executed'"):
            cancel(r, canceller="alice")

    def test_cannot_cancel_cancelled(self):
        r = cancel(_fresh_proposal(), canceller="alice")
        with pytest.raises(RotationError, match="state 'cancelled'"):
            cancel(r, canceller="bob")
