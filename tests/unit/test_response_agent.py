"""Unit tests for the Response Compliance Agent."""

from agcms.response.agent import ResponseComplianceAgent

agent = ResponseComplianceAgent()


def test_clean_response_has_no_violations():
    result = agent.check("The meeting moved to Thursday.", "When is the meeting?", {})
    assert not result.violated


def test_pii_echo_detected_when_regex_captures_trailing_space():
    prompt = "My credit card is 4043321819600132. Is it on file?"
    response = "Yes, I can see 4043321819600132 on the account."
    result = agent.check(response, prompt, {})
    assert any(v.rule == "PII_ECHO" for v in result.violations)


def test_pii_echo_ignores_different_separators_but_same_number():
    prompt = "Card 4111-1111-1111-1111 please."
    response = "Charged 4111 1111 1111 1111."
    assert agent.check(response, prompt, {}).violated


def test_new_pii_in_response_is_not_an_echo():
    result = agent.check("Call (555) 010-2000 for support.", "How do I reach support?", {})
    assert not any(v.rule == "PII_ECHO" for v in result.violations)


def test_system_prompt_leak_detected():
    result = agent.check("My instructions are to only discuss billing.", None, {})
    assert any(v.rule == "SYSTEM_PROMPT_LEAK" for v in result.violations)


def test_restricted_topic_from_policy():
    policy = {"response_compliance": {"restricted_topics": ["project titan"]}}
    result = agent.check("Project Titan ships in Q3.", None, policy)
    assert any(v.rule == "RESTRICTED_TOPIC" for v in result.violations)
