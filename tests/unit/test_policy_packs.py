"""Unit tests for the policy-pack loader.

Verifies the six shipped packs load cleanly, each carries the fields the
UI / resolver rely on (citations, rules, framework id), and that
``merge_packs`` composes base + pack overrides with predictable semantics.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# Point the loader at the repo-rooted packs dir so tests don't depend on
# the /app container layout.
_REPO_ROOT = Path(__file__).resolve().parents[2]
os.environ["AGCMS_POLICY_PACKS_DIR"] = str(_REPO_ROOT / "policies" / "packs")

from agcms.policy.packs import (  # noqa: E402
    _deep_copy_dict,
    list_packs,
    load_pack,
    merge_packs,
)


EXPECTED_PACK_IDS = {
    "hipaa",
    "gdpr",
    "eu-ai-act-high-risk",
    "nist-ai-rmf",
    "soc2-cc",
    "pci-dss",
}


def test_list_packs_includes_all_shipped_packs():
    ids = {p["id"] for p in list_packs()}
    assert EXPECTED_PACK_IDS.issubset(ids), f"missing: {EXPECTED_PACK_IDS - ids}"


def test_list_packs_summary_shape():
    summaries = list_packs()
    assert summaries, "no packs discovered"
    for s in summaries:
        assert set(s.keys()) >= {
            "id", "name", "framework", "version",
            "description", "rule_count", "citations",
        }
        assert isinstance(s["citations"], list)
        assert s["rule_count"] >= 1, f"{s['id']} has no rules"


@pytest.mark.parametrize("pack_id", sorted(EXPECTED_PACK_IDS))
def test_each_pack_loads_and_has_required_fields(pack_id: str):
    pack = load_pack(pack_id)
    assert pack["id"] == pack_id
    assert pack["name"]
    assert pack["framework"]
    assert pack["version"]

    citations = pack.get("metadata", {}).get("framework_citations") or []
    assert citations, f"{pack_id} has no framework_citations"
    for c in citations:
        assert c.get("id") and c.get("title") and c.get("url")

    rules = pack.get("rules") or []
    assert rules, f"{pack_id} has no rules"
    for rule in rules:
        assert rule.get("id")
        assert rule.get("description")
        assert rule.get("action") in {"ALLOW", "REDACT", "BLOCK", "ESCALATE", "LOG"}
        assert rule.get("framework_citations"), f"{rule['id']} missing citations"


def test_load_pack_missing_raises_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_pack("does-not-exist")


def test_merge_packs_overrides_are_applied():
    base = {
        "pii": {"enabled": True, "action_on_detection": "ALLOW", "risk_threshold": "HIGH"},
        "injection": {"enabled": True, "block_threshold": 0.9},
        "audit": {"retention_days": 30},
    }
    merged = merge_packs(base, ["hipaa"])
    # HIPAA tightens the PII threshold and bumps retention.
    assert merged["pii"]["risk_threshold"] == "LOW"
    assert merged["audit"]["retention_days"] >= 2190


def test_merge_packs_last_pack_wins_on_conflict():
    base = {"pii": {"action_on_detection": "ALLOW"}}
    # SOC 2 sets REDACT, PCI DSS sets BLOCK — last one listed wins.
    merged = merge_packs(base, ["soc2-cc", "pci-dss"])
    assert merged["pii"]["action_on_detection"] == "BLOCK"


def test_merge_packs_aggregates_rules_and_citations():
    merged = merge_packs({}, ["hipaa", "soc2-cc"])
    # Every rule id from both packs should survive aggregation.
    rule_ids = {r["id"] for r in merged["rules"]}
    assert any(rid.startswith("hipaa") for rid in rule_ids)
    assert any(rid.startswith("soc2") for rid in rule_ids)
    # Citations aggregate across packs too.
    cit_ids = {c["id"] for c in merged["citations"]}
    assert any("45 CFR" in cid for cid in cit_ids)  # HIPAA cites 45 CFR
    assert any("SOC 2" in cid for cid in cit_ids)
    assert set(merged["active_frameworks"]) == {"HIPAA", "SOC_2"}


def test_merge_packs_empty_pack_list_returns_base_copy():
    base = {"pii": {"enabled": True}}
    merged = merge_packs(base, [])
    assert merged["pii"] == {"enabled": True}
    assert merged["rules"] == []
    assert merged["citations"] == []
    assert merged["active_frameworks"] == []
    # Must be a copy, not an alias — mutating the result must not leak
    # back into the caller's base dict.
    merged["pii"]["enabled"] = False
    assert base["pii"]["enabled"] is True


def test_deep_copy_dict_handles_nested_dicts_and_lists():
    src = {"a": {"b": [1, 2, 3]}, "c": "x"}
    cp = _deep_copy_dict(src)
    # Nested dicts and lists are fresh objects — mutating the copy must
    # not leak back into the source.
    cp["a"]["b"].append(4)
    cp["a"]["new_key"] = "added"
    assert src["a"]["b"] == [1, 2, 3]
    assert "new_key" not in src["a"]
    assert cp["a"] is not src["a"]


def test_pci_dss_blocks_pan():
    pack = load_pack("pci-dss")
    pan_rule = next(r for r in pack["rules"] if r["id"] == "pci-pan-block")
    assert pan_rule["action"] == "BLOCK"
    cats = pan_rule["when"]["pii_categories_any_of"]
    assert "credit_card_number" in cats


def test_eu_ai_act_escalates_rather_than_blocks_critical_pii():
    # Art. 14 requires human oversight before irreversible action.
    pack = load_pack("eu-ai-act-high-risk")
    assert pack["overrides"]["pii"]["critical_action"] == "ESCALATE"
