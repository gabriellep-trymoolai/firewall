import spacy

nlp = spacy.load("en_core_web_sm")

def check_pii(text: str):
    doc = nlp(text)
    pii_entities = []

    for ent in doc.ents:
        if ent.label_ in ["PERSON", "GPE", "DATE", "LOC", "ORG", "CARDINAL"]:
            pii_entities.append((ent.label_, ent.text))

    if pii_entities:
        labels = [label for label, _ in pii_entities]
        return f"PII Detected: {', '.join(set(labels))}"
    return None