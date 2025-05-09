import spacy
import re

nlp = spacy.load("en_core_web_sm")

def check_pii(text: str):
    doc = nlp(text)
    pii_entities = []

    # spaCy-based named entity recognition
    for ent in doc.ents:
        if ent.label_ in ["PERSON", "GPE", "DATE", "LOC", "ORG", "CARDINAL"]:
            pii_entities.append((ent.label_, ent.text))

    # Regex-based pattern matching
    regex_patterns = {
        "Email": r"[\w\.-]+@[\w\.-]+\.\w+",
        "Phone Number": r"(\+?\d{1,2}[\s.-]?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "Credit Card": r"\b(?:\d[ -]*?){13,16}\b",
        "Passport Number": r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b",
        "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "ZIP Code": r"\b\d{5}(?:-\d{4})?\b"
    }

    for label, pattern in regex_patterns.items():
        if re.search(pattern, text):
            pii_entities.append((label, re.search(pattern, text).group()))

    if pii_entities:
        labels = [label for label, _ in pii_entities]
        return f"PII Detected: {', '.join(set(labels))}"
    return None
