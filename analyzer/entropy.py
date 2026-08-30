"""Password entropy estimation module.

Implements theoretical entropy estimation using the formula:
    entropy = password_length × log2(character_set_size)

Important: This is a theoretical estimate only. It does NOT measure
real-world password security, actual cracking time, or probability
of appearing in breach databases.

The formula assumes random password generation from the detected
character set. User-selected passwords often have significantly
lower effective entropy than this estimate suggests due to:
- Human tendencies to create memorable (not random) passwords
- Predictable patterns, common substitutions, and keyboard patterns
- Language-based patterns and semantic structure

Do not use this number as the sole determinant of password security.
Always follow best practices: length, diversity, avoidance of
common passwords and patterns.
"""

from __future__ import annotations

import math
from typing import Dict

from .password_analyzer import _calculate_entropy as _base_entropy


def calculate_entropy(length: int, char_diversity: Dict[str, bool]) -> float:
    """Calculate theoretical entropy estimate.

    Entropy = length × log2(character_set_size)

    Args:
        password_length: Length of the password.
        char_diversity: Dictionary with boolean flags for
            lowercase, uppercase, digits, and special characters.

    Returns:
        Estimated theoretical entropy in bits.

    Note:
        This is a theoretical estimate only. It:
        - Assumes random generation from the character set
        - Does NOT account for human password creation patterns
        - Does NOT measure real-world cracking time
        - Does NOT determine breach database presence
        - Should be used as one factor among many in security evaluation
    """
    return _base_entropy(length, char_diversity)


def entropy_to_bits_display(entropy: float) -> str:
    """Convert entropy value to a human-readable string.

    Args:
        entropy: Entropy value in bits.

    Returns:
        Human-readable string with entropy description.
    """
    if entropy <= 0:
        return "0 bits (no entropy)"

    if entropy < 20:
        category = "Very Low"
    elif entropy < 40:
        category = "Low"
    elif entropy < 60:
        category = "Moderate"
    elif entropy < 80:
        category = "Good"
    elif entropy < 128:
        category = "Strong"
    else:
        category = "Very Strong"

    return f"{entropy:.1f} bits ({category} entropy)"


def search_space_display(search_space: int) -> str:
    """Convert search space to human-readable format.

    Args:
        search_space: Theoretical search space size.

    Returns:
        Human-readable string with search space description.
    """
    if search_space <= 0:
        return "0 (no search space)"

    if search_space < 10 ** 6:
        return f"~{search_space:,} possibilities"

    if search_space < 10 ** 12:
        return f"~{search_space / 10 ** 6:.1f} million possibilities"

    if search_space < 10 ** 20:
        return f"~{search_space / 10 ** 12:.1f} trillion possibilities"

    if search_space < 10 ** 38:
        exponent = int(__import__("math").log10(search_space))
        return f"~10^{exponent:.0f} possibilities"

    return f"> 10^38 possibilities (astronomical)"