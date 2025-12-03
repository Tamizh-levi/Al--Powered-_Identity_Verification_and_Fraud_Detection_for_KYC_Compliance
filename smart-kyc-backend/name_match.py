from difflib import SequenceMatcher


def compare_names(name1: str, name2: str) -> dict:
    """
    Compares two names and returns a match score and verdict using
    SequenceMatcher (native Python library).
    """
    # 1. Normalize (uppercase, remove extra spaces/special chars)
    n1_norm = name1.upper().replace('.', '').replace(',', '').strip()
    n2_norm = name2.upper().replace('.', '').replace(',', '').strip()

    # 2. Sequence Matcher (similarity ratio)
    ratio = SequenceMatcher(None, n1_norm, n2_norm).ratio() * 100

    # 3. Simple token comparison (e.g., check if all words in shorter name are in longer name)
    n1_tokens = set(n1_norm.split())
    n2_tokens = set(n2_norm.split())

    if not n1_tokens or not n2_tokens:
        token_score = 0.0
    else:
        common_tokens = len(n1_tokens.intersection(n2_tokens))
        # Use intersection / length of smaller set for a better "inclusion" score
        min_tokens = min(len(n1_tokens), len(n2_tokens))
        token_score = (common_tokens / min_tokens) * 100 if min_tokens > 0 else 0

    # 4. Final Verdict
    # Use a combination of high ratio OR high token inclusion
    if ratio >= 90 or token_score >= 95:
        verdict = "Strong Match"
        color = "bg-green-100 text-green-800"
    elif ratio >= 75 or token_score >= 75:
        verdict = "Moderate Match (Review Required)"
        color = "bg-yellow-100 text-yellow-800"
    else:
        verdict = "Weak/No Match (Reject)"
        color = "bg-red-100 text-red-800"

    return {
        'ratio': f"{ratio:.2f}%",
        'token_score': f"{token_score:.2f}%",
        'verdict': verdict,
        'color': color,
        'details': f"Aadhaar Name: '{name1}' vs PAN Name: '{name2}'"
    }