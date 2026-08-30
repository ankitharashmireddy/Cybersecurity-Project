"""Core password analysis engine.

This module provides the primary password analysis functionality.
All analysis is performed locally without sending passwords to external services.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Set, Tuple

# Local common passwords dataset - NOT exhaustive, for demonstration only
# In a production system, this would be much larger and sourced securely.
COMMON_PASSWORDS: Set[str] = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "letmein",
    "admin",
    "iloveyou",
    "trustno1",
    "sunshine",
    "princess",
    "football",
    "shadow",
    "master",
    "696969",
    "qwertyuiop",
    "newton",
    "batman",
    "access",
    "123456789",
    "solo",
    "qazwsx",
    "login",
    "dragon",
    "george",
    "qwerty123",
    "shadow",
}


class PasswordAnalysis:
    """Holds the complete analysis result for a password.

    This class encapsulates all analysis dimensions without exposing the
    original password in a way that could lead to logging or leakage.
    """

    def __init__(
        self,
        password: str,
        length: int,
        strength: str,
        score: int,
        length_analysis: Dict,
        char_diversity: Dict,
        common_password: bool,
        repeated_patterns: List[str],
        sequential_patterns: List[str],
        entropy: float,
        search_space: int,
        recommendations: List[str],
    ):
        self._password = password  # Protected - should not be logged or exposed
        self.length = length
        self.strength = strength
        self.score = score
        self.length_analysis = length_analysis
        self.char_diversity = char_diversity
        self.common_password = common_password
        self.repeated_patterns = repeated_patterns
        self.sequential_patterns = sequential_patterns
        self.entropy = entropy
        self.search_space = search_space
        self.recommendations = recommendations

    @property
    def password(self) -> str:
        """Return the password - use with extreme caution.

        This accessor exists for display purposes only.
        In a production system, consider whether this is necessary
        at all given the privacy-first design.
        """
        return self._password

    def __repr__(self) -> str:
        return f"<PasswordAnalysis strength={self.strength} score={self.score} len={self.length}>"


class PatternResult:
    """Result of pattern detection analysis."""

    def __init__(
        self,
        repeated: List[str],
        sequential: List[str],
    ):
        self.repeated = repeated
        self.sequential = sequential


def analyze_password(password: str) -> PasswordAnalysis:
    """Perform complete password analysis.

    This is the main entry point for password analysis. It evaluates
    multiple security dimensions and returns a comprehensive analysis.

    Args:
        password: The password string to analyze.

    Returns:
        PasswordAnalysis containing all evaluation dimensions.

    Note:
        The password is processed in-memory only. No logging, storage,
        or external transmission occurs within this function.
    """
    if not password:
        return _create_empty_analysis(password)

    # 1. Length analysis
    length_analysis = _analyze_length(len(password))

    # 2. Character diversity analysis
    char_diversity = _analyze_char_diversity(password)

    # 3. Common password detection
    common_password = _check_common_password(password)

    # 4. Pattern detection
    pattern_result = _detect_patterns(password)

    # 5. Entropy estimation
    entropy = _calculate_entropy(len(password), char_diversity)

    # 6. Search space estimation
    search_space = _calculate_search_space(len(password), char_diversity)

    # 7. Strength classification and scoring
    strength, score = _classify_strength(
        len(password),
        char_diversity,
        common_password,
        pattern_result,
    )

    # 8. Security recommendations
    recommendations = _generate_recommendations(
        length_analysis,
        char_diversity,
        common_password,
        pattern_result,
    )

    return PasswordAnalysis(
        password=password,
        length=len(password),
        strength=strength,
        score=score,
        length_analysis=length_analysis,
        char_diversity=char_diversity,
        common_password=common_password,
        repeated_patterns=pattern_result.repeated,
        sequential_patterns=pattern_result.sequential,
        entropy=entropy,
        search_space=search_space,
        recommendations=recommendations,
    )


def _create_empty_analysis(password: str) -> PasswordAnalysis:
    """Handle empty password input."""
    return PasswordAnalysis(
        password=password,
        length=0,
        strength="Very Weak",
        score=0,
        length_analysis={"length": 0, "assessment": "Empty password", "min_recommended": 8},
        char_diversity={"lowercase": False, "uppercase": False, "digits": False, "special": False},
        common_password=False,
        repeated_patterns=[],
        sequential_patterns=[],
        entropy=0.0,
        search_space=0,
        recommendations=[
            "Enter a password to evaluate its strength",
            "Use at least 8 characters for basic security",
        ],
    )


def _analyze_length(length: int) -> Dict:
    """Analyze password length and provide assessment."""
    if length == 0:
        return {"length": 0, "assessment": "Empty", "min_recommended": 8, "assessment_detail": "No password provided"}

    min_recommended = 8

    if length >= 16:
        assessment = "Excellent"
        assessment_detail = "Length provides strong resistance to brute-force"
    elif length >= 12:
        assessment = "Good"
        assessment_detail = "Length is above recommended minimum"
    elif length >= 8:
        assessment = "Adequate"
        assessment_detail = "Meets minimum length recommendation"
    elif length >= 4:
        assessment = "Weak"
        assessment_detail = "Too short for secure password use"
    else:
        assessment = "Very Weak"
        assessment_detail = "Extremely short, trivially guessable"

    return {
        "length": length,
        "assessment": assessment,
        "min_recommended": min_recommended,
        "assessment_detail": assessment_detail,
    }


def _analyze_char_diversity(password: str) -> Dict[str, bool | int]:
    """Analyze character diversity in the password.

    Returns dict with per-category presence flags and a diversity ratio.
    """
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    charsets_found = sum([has_lower, has_upper, has_digit, has_special])
    total_possible = 4
    diversity_ratio = charsets_found / total_possible if total_possible > 0 else 0

    return {
        "lowercase": has_lower,
        "uppercase": has_upper,
        "digits": has_digit,
        "special": has_special,
        "charsets_found": charsets_found,
        "total_possible": total_possible,
        "diversity_ratio": diversity_ratio,
    }


def _check_common_password(password: str) -> bool:
    """Check if password appears in common passwords list.

    Note: This uses a small local dataset for demonstration.
    It cannot represent all compromised passwords in real-world breaches.
    """
    password_lower = password.lower()
    return password_lower in COMMON_PASSWORDS


def _detect_patterns(password: str) -> PatternResult:
    """Detect repeated and sequential patterns in password.

    Checks for:
    - Repeated characters (e.g., 'aaaaaaaa')
    - Repeated substrings
    - Sequential patterns (e.g., '123456', 'abcdef', 'qwerty')
    """
    repeated: List[str] = []
    sequential: List[str] = []

    # Detect repeated characters (runs of the same character)
    repeated = _find_repeated_characters(password)

    # Detect sequential patterns
    sequential = _find_sequential_patterns(password)

    return PatternResult(repeated=repeated, sequential=sequential)


def _find_repeated_characters(password: str) -> List[str]:
    """Find runs of repeated characters in the password.

    Returns list of patterns like 'aaaa', '111111', etc.
    """
    repeated: List[str] = []
    if len(password) < 2:
        return repeated

    i = 0
    while i < len(password):
        j = i + 1
        while j < len(password) and password[j] == password[i]:
            j += 1
        run_length = j - i
        if run_length >= 3:  # Only flag runs of 3+ characters
            repeated.append(password[i] * run_length)
        i = j

    return repeated


def _find_sequential_patterns(password: str) -> List[str]:
    """Find sequential/predictable patterns in password.

    Checks for obvious sequences like 123456, abcdef, qwerty, etc.
    """
    sequential: List[str] = []

    # Define known sequential patterns
    seq_patterns_numeric = ["1234", "12345", "123456", "1234567", "12345678", "123456789"]
    seq_patterns_alphabetic = ["abc", "abcdef", "ABC", "ABCDEF"]
    seq_patterns_keyboard = ["qwerty", "asdf", "qazwsx", "1qaz2wsx"]

    password_lower = password.lower()

    # Check numeric sequences
    for pattern in seq_patterns_numeric:
        if pattern in password_lower:
            sequential.append(pattern)

    # Check alphabetic sequences
    for pattern in seq_patterns_alphabetic:
        if pattern in password_lower:
            sequential.append(pattern)

    # Check keyboard pattern
    for pattern in seq_patterns_keyboard:
        if pattern in password_lower:
            sequential.append(pattern)

    # Also check for simple incremental patterns
    # e.g., 123, 234, 345 etc. by checking consecutive characters
    if len(password) >= 3:
        # Check for consecutive ascending numeric
        ascending_count = 0
        descending_count = 0
        for i in range(len(password) - 1):
            curr = ord(password[i])
            next_c = ord(password[i + 1])
            if next_c == curr + 1:
                ascending_count += 1
            elif next_c == curr - 1:
                descending_count += 1
        
        # If most characters form a sequence, flag it
        if ascending_count >= len(password) - 2:
            sequential.append("ascending_sequence")
        if descending_count >= len(password) - 2:
            sequential.append("descending_sequence")

    return sequential


def _calculate_entropy(length: int, char_diversity: Dict[str, bool | int]) -> float:
    """Calculate theoretical entropy estimate.

    entropy = length × log2(character_set_size)

    This is a theoretical estimate assuming random generation from
    the detected character set. It does NOT measure real-world
    password security or cracking time.

    Args:
        password_length: The length of the password.
        char_diversity: Character diversity analysis results.

    Returns:
        Estimated theoretical entropy in bits.
    """
    # Determine character set size based on what's present
    has_lower = char_diversity.get("lowercase", False)
    has_upper = char_diversity.get("uppercase", False)
    has_digit = char_diversity.get("digits", False)
    has_special = char_diversity.get("special", False)

    # Calculate effective character set size
    # If only lowercase: 26
    # If lowercase + uppercase: 52
    # If lowercase + uppercase + digits: 62
    # If all four: ~70+ (26+26+10+special_chars_approx)
    set_size = 26  # base lowercase

    if has_upper:
        set_size += 26
    if has_digit:
        set_size += 10
    if has_special:
        set_size += 32  # approximate special character set

    if length == 0:
        return 0.0

    entropy = length * math.log2(set_size)

    # Cap at reasonable maximum (256 bits) to avoid absurd values
    # This is just a safety cap, not a security assertion
    if entropy > 256:
        entropy = 256.0

    return round(entropy, 2)


def _calculate_search_space(length: int, char_diversity: Dict[str, bool | int]) -> int:
    """Calculate theoretical search space estimate.

    search_space = character_set_size ^ password_length

    Clearly labeled as theoretical estimate only.

    Args:
        password_length: The length of the password.
        char_diversity: Character diversity analysis results.

    Returns:
        Theoretical search space size.
    """
    has_lower = char_diversity.get("lowercase", False)
    has_upper = char_diversity.get("uppercase", False)
    has_digit = char_diversity.get("digits", False)
    has_special = char_diversity.get("special", False)

    # Calculate effective character set size
    set_size = 26  # base lowercase

    if has_upper:
        set_size += 26
    if has_digit:
        set_size += 10
    if has_special:
        set_size += 32  # approximate special character set

    if length == 0:
        return 0

    search_space = set_size ** length

    # Cap at reasonable maximum to avoid overflow
    # 2^64 is approximately 1.8e19, which is already enormous
    # 2^256 is astronomical
    max_reasonable = 2 ** 256
    if search_space > max_reasonable:
        search_space = max_reasonable

    return search_space


def _classify_strength(
    length: int,
    char_diversity: Dict[str, bool | int],
    common_password: bool,
    pattern_result: PatternResult,
) -> Tuple[str, int]:
    """Classify password strength and compute score.

    Scoring is deterministic and based on meaningful factors:
    - Length (max 35 points)
    - Character diversity (max 35 points)
    - Clean password bonus ( +15 points if no common/predictable weaknesses )
    - Common password penalty (up to -40 points)
    - Repeated pattern penalty (up to -25 points)
    - Sequential pattern penalty (up to -20 points)

    Total possible raw score: 85 points
    Score range: 0–100 (capped)

    Args:
        length: Password length.
        char_diversity: Character diversity analysis.
        common_password: Whether password is in common list.
        pattern_result: Pattern detection results.

    Returns:
        Tuple of (strength_label, score_0_to_100).
    """
    score = 0

    # Length scoring (max 35 points)
    # Longer passwords get more points, capped at 35
    if length >= 16:
        score += 35
    elif length >= 12:
        score += 30
    elif length >= 10:
        score += 25
    elif length >= 8:
        score += 20
    elif length >= 6:
        score += 15
    elif length >= 4:
        score += 10
    # length < 4: score += 0

    # Character diversity scoring (max 35 points)
    # Each of the 4 character categories contributes ~8.75 points
    # Full diversity (all 4 categories) earns max 35 points
    charsets_found = char_diversity.get("charsets_found", 0)
    score += charsets_found * 9  # ~9 points per charset, capped at 35

    # Clean password bonus: +10 if no common/predictable weaknesses
    # This bonus is awarded BEFORE penalties, so penalties can still reduce the total
    # Max raw score: 35 (length) + 35 (diversity) + 10 (clean bonus) = 80
    is_clean = not common_password and not pattern_result.repeated and not pattern_result.sequential
    if is_clean:
        score += 10

    # Common password detection (penalty up to -40)
    if common_password:
        score = max(0, score - 40)

    # Repeated pattern penalty (up to -25)
    if pattern_result.repeated:
        penalty = min(25, 5 * len(pattern_result.repeated))
        score = max(0, score - penalty)

    # Sequential pattern penalty (up to -20)
    if pattern_result.sequential:
        penalty = min(20, 5 * len(pattern_result.sequential))
        score = max(0, score - penalty)

    # Ensure minimum score (before final cap)
    score = max(0, score)

    # Final cap at 100 (should not be reached with max raw 85)
    score = min(100, score)

    # Classify strength
    # Thresholds designed so max raw 85 maps to Very Strong (>= 80)
    if score >= 80:
        strength = "Very Strong"
    elif score >= 60:
        strength = "Strong"
    elif score >= 40:
        strength = "Moderate"
    elif score >= 20:
        strength = "Weak"
    else:
        strength = "Very Weak"

    return strength, score


def _generate_recommendations(
    length_analysis: Dict,
    char_diversity: Dict[str, bool | int],
    common_password: bool,
    pattern_result: PatternResult,
) -> List[str]:
    """Generate security recommendations based on analysis.

    Recommendations are specific to detected weaknesses.
    """
    recommendations: List[str] = []

    # Length-based recommendations
    length = length_analysis.get("length", 0)
    assessment = length_analysis.get("assessment", "")

    if length < 8:
        recommendations.append(
            f"Increase password length to at least 8 characters (currently {length})"
        )
    elif length < 12 and assessment not in ["Excellent", "Good"]:
        recommendations.append(
            f"Consider increasing password length to 12+ characters (currently {length})"
        )

    # Character diversity recommendations
    if not char_diversity.get("lowercase", False):
        recommendations.append("Include lowercase characters")
    if not char_diversity.get("uppercase", False):
        recommendations.append("Include uppercase characters")
    if not char_diversity.get("digits", False):
        recommendations.append("Include numbers/digits")
    if not char_diversity.get("special", False):
        recommendations.append("Include special characters (!@#$%^&*)")

    # Common password recommendation
    if common_password:
        recommendations.append(
            "Avoid using commonly encountered passwords - this one is very weak"
        )

    # Repeated pattern recommendations
    if pattern_result.repeated:
        recommendations.append(
            "Avoid repeated character patterns (e.g., 'aaa', '1111')"
        )

    # Sequential pattern recommendations
    if pattern_result.sequential:
        recommendations.append(
            "Avoid predictable sequential patterns (e.g., '1234', 'abcdef', 'qwerty')"
        )

    # General recommendations if password is reasonably strong
    if length >= 12 and char_diversity.get("charsets_found", 0) >= 3 and not common_password and not pattern_result.repeated and not pattern_result.sequential:
        recommendations.append(
            "Consider using a passphrase for increased memorability and security"
        )
        recommendations.append(
            "Consider using a password manager for generating and storing secure passwords"
        )

    return recommendations