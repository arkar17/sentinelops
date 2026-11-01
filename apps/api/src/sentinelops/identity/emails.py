"""Email address normalization and basic validation (no external validator dependency)."""

import re

_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,253}\.[^@\s]{2,63}$")
MAX_EMAIL_LENGTH = 254


def normalize_email(email: str) -> str:
    return email.strip().casefold()


def is_valid_email(email: str) -> bool:
    candidate = email.strip()
    return len(candidate) <= MAX_EMAIL_LENGTH and _EMAIL.fullmatch(candidate) is not None
