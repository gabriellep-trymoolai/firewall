from perspective import PerspectiveAPI

client = PerspectiveAPI()

def check_toxicity(text: str):
    scores = client.score(text, attributes=["TOXICITY", "SEVERE_TOXICITY", "INSULT", "THREAT", "IDENTITY_ATTACK"])
    for label, score in scores.items():
        if score > 0.7:
            return label
    return None
