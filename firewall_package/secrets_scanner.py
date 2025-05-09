import re
import math

def shannon_entropy(data: str) -> float:
    if not data:
        return 0
    freq = {char: data.count(char) for char in set(data)}
    probs = [f / len(data) for f in freq.values()]
    return -sum(p * math.log2(p) for p in probs)

def check_secrets(text: str, entropy_threshold: float = 4.5) -> bool:
    # Entropy-based detection
    tokens = text.split()
    for token in tokens:
        if len(token) > 20 and shannon_entropy(token) > entropy_threshold:
            return True

    # Regex-based detection
    secret_patterns = [
        r"sk-[A-Za-z0-9]{20,40}",
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"ghp_[A-Za-z0-9]{36}",
        r"glpat-[A-Za-z0-9\-]{20,}",
        r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
        r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+:[A-Za-z0-9!@#$%^&*()_+=\-]+",
        r"(?i)(api|access|secret|private)?[-_ ]?(key|token|pwd|pass)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9\-_.:+/]{16,}",
        r"(?i)password[\"']?\s*[:=]\s*[\"']?.{4,}"
    ]

    for pattern in secret_patterns:
        if re.search(pattern, text):
            return True

    return False