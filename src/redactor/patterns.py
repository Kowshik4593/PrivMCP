# src/redactor/patterns.py

import re

PHI_REGEXES = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),  # Social Security Number
    (r"\(\d{3}\)\s?\d{3}-\d{4}", "PHONE"),  # US Phone (with area code)
    (r"\b\d{3}-\d{3}-\d{4}\b", "PHONE"),  # US Phone
    (r"\b\d{1,2}/\d{1,2}/\d{4}\b", "DATE"),  # Date mm/dd/yyyy
    (r"\bMRN[:\s]*\d+\b", "MRN"),
    (r"\bDOB[:\s]*\d{1,2}/\d{1,2}/\d{4}\b", "DOB"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL"),
    (r"\b\d+\s+[A-Za-z]+\s+[A-Za-z]+\b", "ADDRESS"),
    (r"\b\d{5}(?:-\d{4})?\b", "ZIP"),
    (r"\b(?:[A-Z][a-z]+\s){1,3}[A-Z][a-z]+\b", "PERSON"),  # crude person name (capitalize)
]
