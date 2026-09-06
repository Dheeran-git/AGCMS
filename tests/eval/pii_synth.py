"""Synthetic PII prompt generator with gold entity spans.

Every prompt embeds one to three PII values from a fixed type set into an
enterprise-style sentence. Spans are recorded exactly, so the harness can
score entity-level precision and recall, not just prompt-level detection.
"""

from __future__ import annotations

import random
from typing import Callable

from faker import Faker

TEMPLATES = [
    "Hi team, please update the record for {A}. Thanks.",
    "Customer called about their account. Details: {A}. Can you draft a reply?",
    "Forward the invoice to {A} and cc finance.",
    "Summarize this ticket: user reports login failure, contact is {A}.",
    "Translate to French: our client's reference is {A}.",
    "Write a polite reminder email mentioning {A} and {B}.",
    "Patient intake note: {A}, {B}. Suggest follow-up questions.",
    "Verify these onboarding fields: {A}; {B}; {C}.",
    "Draft a support macro. Example case: {A} reported an issue with {B}.",
    "Extract the key facts: {A} / {B}",
]


def _ssn(f: Faker) -> str:
    return f"{random.randint(100, 899)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"


def _credit_card(f: Faker) -> str:
    raw = f.credit_card_number(card_type="visa16")
    return " ".join(raw[i:i + 4] for i in range(0, 16, 4)) if random.random() < 0.5 else raw


def _phone_us(f: Faker) -> str:
    a, b, c = random.randint(200, 989), random.randint(200, 999), random.randint(1000, 9999)
    return random.choice([f"({a}) {b}-{c}", f"{a}-{b}-{c}", f"+1 {a} {b} {c}"])


def _aadhaar(f: Faker) -> str:
    return f"{random.randint(2000, 9999)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}"


def _pan(f: Faker) -> str:
    letters = "".join(random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(5))
    return f"{letters}{random.randint(1000, 9999)}{random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ')}"


def _iban(f: Faker) -> str:
    return f.iban()


def _dob(f: Faker) -> str:
    d = f.date_of_birth(minimum_age=18, maximum_age=80)
    return d.strftime(random.choice(["%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y"]))


def _ip(f: Faker) -> str:
    return f.ipv4_public()


def _mrn(f: Faker) -> str:
    return f"MRN-{random.randint(100000, 99999999)}"


def _person(f: Faker) -> str:
    return f.name()


GENERATORS: dict[str, Callable[[Faker], str]] = {
    "EMAIL": lambda f: f.email(),
    "PHONE_US": _phone_us,
    "SSN": _ssn,
    "CREDIT_CARD": _credit_card,
    "AADHAAR": _aadhaar,
    "PAN": _pan,
    "IBAN": _iban,
    "DATE_OF_BIRTH": _dob,
    "IP_ADDRESS": _ip,
    "MRN": _mrn,
    "PERSON_NAME": _person,
}

# Prefixes that make a bare value read naturally in a sentence.
PREFIXES = {
    "EMAIL": ["email ", "reach them at ", ""],
    "PHONE_US": ["phone ", "call ", "mobile: "],
    "SSN": ["SSN ", "social security number ", "SSN: "],
    "CREDIT_CARD": ["card ", "card number ", "paid with "],
    "AADHAAR": ["Aadhaar ", "Aadhaar number ", "UID "],
    "PAN": ["PAN ", "PAN card ", "tax id "],
    "IBAN": ["IBAN ", "bank account ", "transfer to "],
    "DATE_OF_BIRTH": ["DOB ", "born ", "date of birth "],
    "IP_ADDRESS": ["from IP ", "server ", "address "],
    "MRN": ["record ", "", "patient "],
    "PERSON_NAME": ["", "name: ", "customer "],
}


def generate(n: int, seed: int = 42) -> list[dict]:
    """Return ``n`` prompts, each with a list of gold spans."""
    random.seed(seed)
    fake = Faker()
    Faker.seed(seed)
    types = list(GENERATORS)
    out = []
    for _ in range(n):
        template = random.choice(TEMPLATES)
        slots = [s for s in ("A", "B", "C") if "{" + s + "}" in template]
        chosen = random.sample(types, k=len(slots))
        text = template
        spans = []
        # Fill slots left to right so recorded offsets stay valid.
        for slot, etype in zip(slots, chosen):
            value = GENERATORS[etype](fake)
            prefix = random.choice(PREFIXES[etype])
            marker = "{" + slot + "}"
            pos = text.index(marker)
            text = text[:pos] + prefix + value + text[pos + len(marker):]
            start = pos + len(prefix)
            spans.append({"start": start, "end": start + len(value), "type": etype})
        for s in spans:
            assert text[s["start"]:s["end"]], (text, s)
        out.append({"text": text, "spans": spans, "label": 1, "source": "faker-synthetic"})
    return out
