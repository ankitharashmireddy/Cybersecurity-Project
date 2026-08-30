"""Password pattern detection module.

Detects repeated characters, repeated substrings, and sequential patterns
that indicate weak or predictable passwords.

All detection is performed locally on the password string without
any external network calls.
"""

from __future__ import annotations

from typing import List

from .password_analyzer import PatternResult


def detect_patterns(password: str) -> PatternResult:
    """Detect repeated and sequential patterns in a password.

    This is the main entry point for pattern detection.

    Args:
        password: The password string to analyze.

    Returns:
        PatternResult containing detected repeated and sequential patterns.

    Note:
        Detection is purely syntactic - it identifies patterns that
        are generally considered weak, but their presence does not
        guarantee the password has been compromised in a breach.
    """
    if not password or len(password) < 3:
        return PatternResult(repeated=[], sequential=[])

    return PatternResult(
        repeated=_find_repeated_characters(password),
        sequential=_find_sequential_patterns(password),
    )


def _find_repeated_characters(password: str) -> List[str]:
    """Find runs of repeated characters (3+ in a row).

    Examples detected:
    - 'aaaaaaaa' → ['aaaaaaaa']
    - '11111111' → ['11111111']
    - 'PasswordPassword' → detected via repeated substring

    Returns:
        List of repeated pattern strings found.
    """
    repeated: List[str] = []
    if len(password) < 3:
        return repeated

    i = 0
    while i < len(password):
        j = i + 1
        while j < len(password) and password[j] == password[i]:
            j += 1
        run_length = j - i
        if run_length >= 3:
            repeated.append(password[i] * run_length)
        i = j

    return repeated


def _find_repeated_substrings(password: str, min_length: int = 2) -> List[str]:
    """Find repeated substrings in the password.

    Detects patterns like 'abab' or 'PasswordPassword'.

    Args:
        password: The password string.
        min_length: Minimum substring length to consider.

    Returns:
        List of repeated substring patterns found.
    """
    repeated: List[str] = []
    if len(password) < 2 * min_length:
        return repeated

    # Check for repeated substrings of increasing length
    for length in range(min_length, len(password) // 2 + 1):
        for start in range(len(password) - 2 * length + 1):
            substr = password[start:start + length]
            remaining = password[start + length:]
            if remaining.startswith(substr):
                # Avoid duplicates
                if substr not in repeated:
                    repeated.append(substr)

    return repeated


def _find_sequential_patterns(password: str) -> List[str]:
    """Find sequential/predictable patterns in the password.

    Checks for:
    - Numeric sequences: 1234, 123456, etc.
    - Alphabetic sequences: abc, abcdef, ABC, ABCDEF
    - Keyboard patterns: qwerty, asdf, qazwsx
    - Simple incremental/decremental patterns

    Returns:
        List of sequential pattern strings found.
    """
    sequential: List[str] = []

    # Define known sequential patterns
    seq_patterns = {
        "numeric": ["1234", "12345", "123456", "1234567", "12345678", "123456789"],
        "alpha_lower": ["abc", "abcd", "abcde", "abcdef", "ABC", "ABCD", "ABCDE", "ABCDEF"],
        "keyboard": ["qwerty", "asdf", "qazwsx", "1qaz2wsx", "1qazxsw"],
    }

    password_lower = password.lower()

    # Check numeric sequences
    for pattern in seq_patterns["numeric"]:
        if pattern in password_lower:
            sequential.append(pattern)

    # Check alphabetic sequences
    for pattern in seq_patterns["alpha_lower"]:
        if pattern in password_lower:
            sequential.append(pattern)

    # Check keyboard patterns
    for pattern in seq_patterns["keyboard"]:
        if pattern in password_lower:
            sequential.append(pattern)

    # Check for simple incremental character sequences
    # by looking at consecutive character codes
    if len(password) >= 3:
        asc = 0
        desc = 0
        for i in range(len(password) - 1):
            diff = ord(password[i + 1]) - ord(password[i])
            if diff == 1:
                asc += 1
            elif diff == -1:
                desc += 1

        # If a large majority of chars form a sequence
        if asc >= len(password) - 2 and asc > 0:
            sequential.append("ascending_consecutive")
        if desc >= len(password) - 2 and desc > 0:
            sequential.append("descending_consecutive")

    return sequential