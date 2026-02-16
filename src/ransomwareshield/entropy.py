"""Entropy calculation utilities for detecting encrypted content."""

import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Returns a value between 0.0 (completely uniform) and 8.0
    (maximally random / encrypted).
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def file_entropy(filepath: str) -> float:
    """Calculate the Shannon entropy of a file's contents.

    Returns 0.0 if the file cannot be read.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        return calculate_entropy(data)
    except (OSError, IOError):
        return 0.0
