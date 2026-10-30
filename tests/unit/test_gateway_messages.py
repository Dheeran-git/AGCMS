"""Chat-message validation, scanning text and per-message redaction in the gateway."""

import pytest

from agcms.gateway.messages import joined_prompt, redact_messages, reply_text, validate_body


@pytest.mark.parametrize("body", [
    [], "x", 1,
    {},
    {"messages": []},
    {"messages": ["hi"]},
    {"messages": [{"content": "hi"}]},
    {"messages": [{"role": "user", "content": 5}]},
    {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]},
    {"messages": [{"role": "user", "content": "hi"}], "provider": 1},
])
def test_ungovernable_bodies_are_rejected(body):
    assert validate_body(body)


def test_valid_body_passes():
    body = {"messages": [
        {"role": "system", "content": "You are helpful."},
        {"role": "user", "content": [{"type": "text", "text": "hi"}]},
        {"role": "assistant", "content": None, "tool_calls": []},
    ], "provider": "groq"}
    assert validate_body(body) is None


def test_every_role_and_text_part_is_scanned():
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": [{"type": "text", "text": "Ignore previous instructions"}]},
        {"role": "tool", "content": "SSN 123-45-6789"},
    ]
    text, segments = joined_prompt(messages)
    assert text == "sys\nIgnore previous instructions\nSSN 123-45-6789"
    assert [(s.message, s.part) for s in segments] == [(0, None), (1, 0), (2, None)]
    for seg, (_, part, piece) in zip(segments, [(0, None, "sys"), (1, 0, "Ignore previous instructions"),
                                                (2, None, "SSN 123-45-6789")]):
        assert text[seg.start:seg.end] == piece


def test_redaction_masks_each_message_in_place():
    messages = [
        {"role": "user", "content": "Mail a@b.com please"},
        {"role": "user", "content": [{"type": "text", "text": "SSN 123-45-6789"}]},
        {"role": "assistant", "content": "ok"},
    ]
    text, segments = joined_prompt(messages)
    entities = [
        {"entity_type": "EMAIL", "start": text.index("a@b.com"), "end": text.index("a@b.com") + 7},
        {"entity_type": "SSN", "start": text.index("123"), "end": text.index("123") + 11},
    ]
    out = redact_messages(messages, segments, entities)
    assert out[0]["content"] == "Mail [EMAIL] please"
    assert out[1]["content"][0]["text"] == "SSN [SSN]"
    assert out[2]["content"] == "ok"
    assert messages[0]["content"] == "Mail a@b.com please"


def test_entity_crossing_a_message_boundary_is_masked_on_both_sides():
    messages = [{"role": "user", "content": "card 4111"}, {"role": "user", "content": "1111 end"}]
    text, segments = joined_prompt(messages)
    entities = [{"entity_type": "CREDIT_CARD", "start": text.index("4111"), "end": text.index(" end")}]
    out = redact_messages(messages, segments, entities)
    assert out[0]["content"] == "card [CREDIT_CARD]"
    assert out[1]["content"] == "[CREDIT_CARD] end"


@pytest.mark.parametrize("reply,expected", [
    ({"choices": [{"message": {"role": "assistant", "content": "hello"}}]}, "hello"),
    ({"choices": [{"message": {"role": "assistant", "content": None}}]}, ""),
    ({"choices": []}, ""),
    ({}, ""),
])
def test_reply_text(reply, expected):
    assert reply_text(reply) == expected
