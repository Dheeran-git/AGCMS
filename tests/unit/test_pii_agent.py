"""Unit tests for the AGCMS PII Detection Agent.

50+ tests covering:
  - All regex pattern types (20+ patterns)
  - spaCy NER detection (person names, organizations)
  - Masking correctness
  - Deduplication of overlapping entities
  - Risk level scoring
  - Custom tenant patterns
  - Edge cases and false positive resistance
"""

import pytest

from agcms.pii.agent import PIIAgent
from agcms.pii.models import PIIEntity, PIIScanResult
from agcms.pii.patterns import luhn_check, validate_ip_address


@pytest.fixture(scope="module")
def agent():
    """Shared PIIAgent instance (spaCy model loaded once)."""
    return PIIAgent()


EMPTY_POLICY: dict = {}


# ==================================================================
# 1. Regex Pattern Detection (one test per pattern type)
# ==================================================================


class TestRegexPatterns:
    @pytest.mark.asyncio
    async def test_detects_email(self, agent):
        result = await agent.scan("Contact john.doe@acmecorp.com for details.", EMPTY_POLICY)
        assert result.has_pii
        assert any(e.entity_type == "EMAIL" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_phone_us(self, agent):
        result = await agent.scan("Call me at (555) 123-4567 today.", EMPTY_POLICY)
        assert any(e.entity_type == "PHONE_US" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_phone_intl(self, agent):
        result = await agent.scan("Reach me at +44 20 7946 0958 please.", EMPTY_POLICY)
        assert result.has_pii

    @pytest.mark.asyncio
    async def test_detects_ssn(self, agent):
        result = await agent.scan("Patient SSN is 123-45-6789.", EMPTY_POLICY)
        assert any(e.entity_type == "SSN" for e in result.entities)
        assert result.risk_level == "CRITICAL"

    @pytest.mark.asyncio
    async def test_detects_ssn_no_dashes(self, agent):
        result = await agent.scan("SSN: 123 45 6789 on file.", EMPTY_POLICY)
        assert any(e.entity_type == "SSN" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_credit_card_visa(self, agent):
        result = await agent.scan("Card number: 4111 1111 1111 1111", EMPTY_POLICY)
        assert any(e.entity_type == "CREDIT_CARD" for e in result.entities)

    @pytest.mark.asyncio
    async def test_rejects_invalid_credit_card(self, agent):
        """A number failing the Luhn check should not be flagged."""
        result = await agent.scan("Number: 1234 5678 9012 3456", EMPTY_POLICY)
        cc_entities = [e for e in result.entities if e.entity_type == "CREDIT_CARD"]
        assert len(cc_entities) == 0

    @pytest.mark.asyncio
    async def test_detects_aadhaar(self, agent):
        result = await agent.scan("Aadhaar: 2345 6789 0123", EMPTY_POLICY)
        assert any(e.entity_type == "AADHAAR" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_pan(self, agent):
        result = await agent.scan("PAN card: ABCDE1234F", EMPTY_POLICY)
        assert any(e.entity_type == "PAN" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_ip_address(self, agent):
        result = await agent.scan("Server at 192.168.1.100 is down.", EMPTY_POLICY)
        assert any(e.entity_type == "IP_ADDRESS" for e in result.entities)

    @pytest.mark.asyncio
    async def test_rejects_invalid_ip(self, agent):
        """IP with octet > 255 should not match."""
        result = await agent.scan("Version 300.400.500.600 released.", EMPTY_POLICY)
        ip_entities = [e for e in result.entities if e.entity_type == "IP_ADDRESS"]
        assert len(ip_entities) == 0

    @pytest.mark.asyncio
    async def test_detects_iban(self, agent):
        result = await agent.scan("Transfer to GB29NWBK60161331926819.", EMPTY_POLICY)
        assert any(e.entity_type == "IBAN" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_date_of_birth(self, agent):
        result = await agent.scan("DOB: 15/06/1990 on record.", EMPTY_POLICY)
        assert any(e.entity_type == "DATE_OF_BIRTH" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_passport(self, agent):
        result = await agent.scan("Passport: A12345678", EMPTY_POLICY)
        assert any(e.entity_type == "PASSPORT" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_mrn(self, agent):
        result = await agent.scan("Patient MRN-20290043 admitted.", EMPTY_POLICY)
        assert any(e.entity_type == "MRN" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_mac_address(self, agent):
        result = await agent.scan("Device MAC: 00:1A:2B:3C:4D:5E", EMPTY_POLICY)
        assert any(e.entity_type == "MAC_ADDRESS" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_aws_access_key(self, agent):
        result = await agent.scan("Key: AKIAIOSFODNN7EXAMPLE", EMPTY_POLICY)
        assert any(e.entity_type == "AWS_ACCESS_KEY" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_url_with_credentials(self, agent):
        result = await agent.scan("DB at https://admin:p4ssw0rd@db.internal.com/prod", EMPTY_POLICY)
        assert any(e.entity_type == "URL_WITH_CREDENTIALS" for e in result.entities)

    @pytest.mark.asyncio
    async def test_detects_multiple_emails(self, agent):
        text = "Send to alice@company.com and bob@company.com"
        result = await agent.scan(text, EMPTY_POLICY)
        email_entities = [e for e in result.entities if e.entity_type == "EMAIL"]
        assert len(email_entities) == 2


# ==================================================================
# 2. spaCy NER Detection
# ==================================================================


class TestNERDetection:
    @pytest.mark.asyncio
    async def test_detects_person_name(self, agent):
        result = await agent.scan("Schedule a meeting with Dr. John Smith tomorrow.", EMPTY_POLICY)
        person_entities = [e for e in result.entities if e.entity_type == "PERSON_NAME"]
        assert len(person_entities) >= 1

    @pytest.mark.asyncio
    async def test_detects_organization(self, agent):
        result = await agent.scan("She works at Goldman Sachs in New York.", EMPTY_POLICY)
        org_entities = [e for e in result.entities if e.entity_type == "ORGANIZATION"]
        assert len(org_entities) >= 1

    @pytest.mark.asyncio
    async def test_ner_combined_with_regex(self, agent):
        text = "Email john.smith@corp.com about John Smith's account."
        result = await agent.scan(text, EMPTY_POLICY)
        types = {e.entity_type for e in result.entities}
        assert "EMAIL" in types


# ==================================================================
# 3. Masking
# ==================================================================


class TestMasking:
    @pytest.mark.asyncio
    async def test_mask_email(self, agent):
        text = "Contact john@corp.com for details."
        result = await agent.scan(text, EMPTY_POLICY)
        masked = result.mask(text)
        assert "john@corp.com" not in masked
        assert "[EMAIL]" in masked

    @pytest.mark.asyncio
    async def test_mask_ssn(self, agent):
        text = "SSN is 123-45-6789 on file."
        result = await agent.scan(text, EMPTY_POLICY)
        masked = result.mask(text)
        assert "123-45-6789" not in masked
        assert "[SSN]" in masked

    @pytest.mark.asyncio
    async def test_mask_preserves_surrounding_text(self, agent):
        text = "Please contact alice@test.com or call 555-123-4567 for details"
        result = await agent.scan(text, EMPTY_POLICY)
        masked = result.mask(text)
        assert "Please contact" in masked
        assert "for details" in masked

    @pytest.mark.asyncio
    async def test_mask_multiple_entities(self, agent):
        text = "Name: John, SSN: 123-45-6789, email: john@test.com"
        result = await agent.scan(text, EMPTY_POLICY)
        masked = result.mask(text)
        assert "123-45-6789" not in masked
        assert "john@test.com" not in masked

    @pytest.mark.asyncio
    async def test_mask_no_pii_returns_original(self, agent):
        text = "What is the capital of France?"
        result = await agent.scan(text, EMPTY_POLICY)
        masked = result.mask(text)
        assert masked == text


# ==================================================================
# 4. Deduplication
# ==================================================================


class TestDeduplication:
    def test_dedup_non_overlapping(self):
        entities = [
            PIIEntity("a@b.com", "EMAIL", 0, 7, 1.0),
            PIIEntity("123-45-6789", "SSN", 20, 31, 1.0),
        ]
        result = PIIAgent._deduplicate(entities)
        assert len(result) == 2

    def test_dedup_overlapping_keeps_higher_confidence(self):
        entities = [
            PIIEntity("John Smith", "PERSON_NAME", 0, 10, 0.85),
            PIIEntity("John", "PERSON_NAME", 0, 4, 0.70),
        ]
        result = PIIAgent._deduplicate(entities)
        assert len(result) == 1
        assert result[0].confidence == 0.85

    def test_dedup_adjacent_entities_kept(self):
        entities = [
            PIIEntity("a@b.com", "EMAIL", 0, 7, 1.0),
            PIIEntity("c@d.com", "EMAIL", 7, 14, 1.0),
        ]
        result = PIIAgent._deduplicate(entities)
        assert len(result) == 2


# ==================================================================
# 5. Risk Scoring
# ==================================================================


class TestRiskScoring:
    def test_no_entities_is_none(self):
        assert PIIAgent._compute_risk([]) == "NONE"

    def test_ssn_is_critical(self):
        entities = [PIIEntity("123-45-6789", "SSN", 0, 11, 1.0)]
        assert PIIAgent._compute_risk(entities) == "CRITICAL"

    def test_credit_card_is_critical(self):
        entities = [PIIEntity("4532015112345678", "CREDIT_CARD", 0, 16, 1.0)]
        assert PIIAgent._compute_risk(entities) == "CRITICAL"

    def test_aadhaar_is_critical(self):
        entities = [PIIEntity("2345 6789 0123", "AADHAAR", 0, 14, 1.0)]
        assert PIIAgent._compute_risk(entities) == "CRITICAL"

    def test_three_low_risk_is_high(self):
        entities = [
            PIIEntity("a@b.com", "EMAIL", 0, 7, 1.0),
            PIIEntity("John", "PERSON_NAME", 10, 14, 0.85),
            PIIEntity("192.168.1.1", "IP_ADDRESS", 20, 31, 1.0),
        ]
        assert PIIAgent._compute_risk(entities) == "HIGH"

    def test_single_email_is_medium(self):
        entities = [PIIEntity("a@b.com", "EMAIL", 0, 7, 1.0)]
        assert PIIAgent._compute_risk(entities) == "MEDIUM"

    def test_iban_is_critical(self):
        entities = [PIIEntity("GB29NWBK60161331926819", "IBAN", 0, 22, 1.0)]
        assert PIIAgent._compute_risk(entities) == "CRITICAL"

    def test_mrn_is_critical(self):
        entities = [PIIEntity("MRN-20290043", "MRN", 0, 12, 1.0)]
        assert PIIAgent._compute_risk(entities) == "CRITICAL"


# ==================================================================
# 6. Clean Text (no PII)
# ==================================================================


class TestCleanText:
    @pytest.mark.asyncio
    async def test_clean_text_no_pii(self, agent):
        result = await agent.scan("What is the capital of France?", EMPTY_POLICY)
        assert not result.has_pii
        assert result.risk_level == "NONE"

    @pytest.mark.asyncio
    async def test_clean_code_snippet(self, agent):
        result = await agent.scan("def hello(): return 'world'", EMPTY_POLICY)
        assert result.risk_level in ("NONE", "MEDIUM")  # NER may find entities in code

    @pytest.mark.asyncio
    async def test_empty_string(self, agent):
        result = await agent.scan("", EMPTY_POLICY)
        assert not result.has_pii
        assert result.risk_level == "NONE"


# ==================================================================
# 7. Custom Patterns (tenant policy)
# ==================================================================


class TestCustomPatterns:
    @pytest.mark.asyncio
    async def test_custom_employee_id_pattern(self, agent):
        policy = {"custom_patterns": {"EMPLOYEE_ID": r"EMP-\d{6}"}}
        result = await agent.scan("Employee EMP-123456 submitted.", policy)
        assert any(e.entity_type == "EMPLOYEE_ID" for e in result.entities)

    @pytest.mark.asyncio
    async def test_custom_project_code_pattern(self, agent):
        policy = {"custom_patterns": {"PROJECT_CODE": r"PRJ-[A-Z]{3}-\d{4}"}}
        result = await agent.scan("Working on PRJ-ABC-2026 today.", policy)
        assert any(e.entity_type == "PROJECT_CODE" for e in result.entities)

    @pytest.mark.asyncio
    async def test_custom_pattern_combined_with_builtin(self, agent):
        policy = {"custom_patterns": {"EMPLOYEE_ID": r"EMP-\d{6}"}}
        text = "Employee EMP-123456 email: emp@corp.com"
        result = await agent.scan(text, policy)
        types = {e.entity_type for e in result.entities}
        assert "EMPLOYEE_ID" in types
        assert "EMAIL" in types


# ==================================================================
# 8. Luhn Algorithm (credit card validation)
# ==================================================================


class TestLuhnCheck:
    def test_valid_visa(self):
        assert luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert luhn_check("5425233430109903") is True

    def test_invalid_number(self):
        assert luhn_check("1234567890123456") is False

    def test_too_short(self):
        assert luhn_check("12345") is False

    def test_strips_spaces(self):
        assert luhn_check("4111 1111 1111 1111") is True


# ==================================================================
# 9. IP Address Validation
# ==================================================================


class TestIPValidation:
    def test_valid_ip(self):
        assert validate_ip_address("192.168.1.100") is True

    def test_invalid_octet(self):
        assert validate_ip_address("300.400.500.600") is False

    def test_all_zeros(self):
        assert validate_ip_address("0.0.0.0") is False


# ==================================================================
# 10. Model classes
# ==================================================================


class TestModels:
    def test_pii_scan_result_has_pii(self):
        result = PIIScanResult(entities=[PIIEntity("test", "EMAIL", 0, 4, 1.0)])
        assert result.has_pii is True

    def test_pii_scan_result_no_pii(self):
        result = PIIScanResult()
        assert result.has_pii is False

    def test_pii_scan_result_entity_types(self):
        result = PIIScanResult(entities=[
            PIIEntity("a", "EMAIL", 0, 1, 1.0),
            PIIEntity("b", "SSN", 2, 3, 1.0),
            PIIEntity("c", "EMAIL", 4, 5, 1.0),
        ])
        types = result.entity_types
        assert set(types) == {"EMAIL", "SSN"}
