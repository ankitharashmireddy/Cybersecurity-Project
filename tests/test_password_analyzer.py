"""Unit tests for the password strength analyzer.

Test cases cover the full range of password scenarios including:
- Very short password
- Common password
- Numbers only
- Lowercase only
- Uppercase only
- Mixed character password
- Long passphrase
- Repeated characters
- Sequential characters
- Special characters
- Empty input
- Boundary cases

All tests use non-personal, educational password examples.
"""

from __future__ import annotations

import pytest

from analyzer.pattern_checker import detect_patterns
from analyzer.password_analyzer import analyze_password
from analyzer.entropy import calculate_entropy, entropy_to_bits_display, search_space_display


# Very short password
very_short_password = "ab"
# Common password
common_pw = "password"
# Numbers only
numbers_only = "123456"
# Lowercase only
lowercase_only = "hello"
# Uppercase only
uppercase_only = "HELLO"
# Mixed character password (12 chars with all types)
mixed_password = "Abc123!xYz9Wq"
# Long passphrase (30+ chars with all character types for Strong rating)
long_passphrase = "CorrectHorse99BatteryStaple!Now"
# Repeated characters
repeated_chars = "aaaaaaaa"
# Sequential characters
sequential = "123456"
# Special characters
special_chars = "!@#$%^&*"
# Empty input
empty_input = ""


class TestPasswordAnalysis:
    """Tests for PasswordAnalysis class and analyze_password function."""

    def test_very_short_password(self):
        """Very short passwords should be Very Weak."""
        result = analyze_password(very_short_password)
        assert result.strength == "Very Weak"
        assert result.length < 4
        assert result.score < 20

    def test_common_password(self):
        """Common passwords should receive severe penalty."""
        result = analyze_password(common_pw)
        assert result.common_password is True
        # Common password should significantly lower the score
        assert result.score < 40
        # Check that a common password recommendation is present
        assert any("commonly encountered" in r for r in result.recommendations)

    def test_numbers_only(self):
        """Numbers-only passwords should have limited character diversity."""
        result = analyze_password(numbers_only)
        assert result.char_diversity["lowercase"] is False
        assert result.char_diversity["uppercase"] is False
        assert result.char_diversity["digits"] is True
        assert result.char_diversity["special"] is False
        # Should be Weak or Very Weak due to lack of diversity
        assert result.strength in ("Very Weak", "Weak")

    def test_lowercase_only(self):
        """Lowercase-only passwords should have limited diversity."""
        result = analyze_password(lowercase_only)
        assert result.char_diversity["lowercase"] is True
        assert result.char_diversity["uppercase"] is False
        assert result.char_diversity["digits"] is False
        assert result.char_diversity["special"] is False
        assert result.strength in ("Very Weak", "Weak", "Moderate")

    def test_uppercase_only(self):
        """Uppercase-only passwords should have limited diversity."""
        result = analyze_password(uppercase_only)
        assert result.char_diversity["lowercase"] is False
        assert result.char_diversity["uppercase"] is True
        assert result.char_diversity["digits"] is False
        assert result.char_diversity["special"] is False
        assert result.strength in ("Very Weak", "Weak", "Moderate")

    def test_mixed_character_password(self):
        """Mixed character passwords should score well for diversity."""
        result = analyze_password(mixed_password)
        assert result.char_diversity["lowercase"] is True
        assert result.char_diversity["uppercase"] is True
        assert result.char_diversity["digits"] is True
        assert result.char_diversity["special"] is True
        # Mixed chars should be at least Moderate
        assert result.strength in ("Moderate", "Strong", "Very Strong")

    def test_long_passphrase(self):
        """Long passphrases should score well for length."""
        result = analyze_password(long_passphrase)
        assert result.length >= 20
        assert result.length_analysis["assessment"] in ("Good", "Excellent")
        # Passphrase should be Strong or Very Strong
        assert result.strength in ("Strong", "Very Strong")

    def test_repeated_characters(self):
        """Passwords with repeated characters should be penalized."""
        result = analyze_password(repeated_chars)
        assert len(result.repeated_patterns) > 0
        # Repeated chars should lower the strength
        assert result.strength in ("Very Weak", "Weak")

    def test_sequential_patterns(self):
        """Passwords with sequential patterns should be penalized."""
        result = analyze_password(sequential)
        assert len(result.sequential_patterns) > 0
        # Sequential patterns should lower the strength
        assert result.strength in ("Very Weak", "Weak", "Moderate")

    def test_special_characters(self):
        """Passwords with special characters should gain diversity points."""
        result = analyze_password(special_chars)
        assert result.char_diversity["special"] is True
        # Special chars alone (no other types) still weak
        assert result.strength in ("Very Weak", "Weak")

    def test_empty_input(self):
        """Empty input should produce a specific analysis."""
        result = analyze_password(empty_input)
        assert result.length == 0
        assert result.strength == "Very Weak"
        assert result.score == 0

    def test_entropy_calculation(self):
        """Entropy should be calculated for mixed password."""
        result = analyze_password(mixed_password)
        assert result.entropy > 0
        # Should have reasonable entropy for an 8-char mixed password
        assert result.entropy >= 30  # 8 * log2(~70) ≈ 8 * 6.1 = 48.8, but penalized

    def test_search_space_calculation(self):
        """Search space should be calculated for mixed password."""
        result = analyze_password(mixed_password)
        assert result.search_space > 0
        # 8 chars from ~70 character set = 70^8 possibilities

    def test_recommendations_for_weak(self):
        """Weak passwords should get length increase recommendations."""
        result = analyze_password(very_short_password)
        # Should recommend increasing length
        length_recs = [r for r in result.recommendations if "length" in r.lower()]
        assert len(length_recs) > 0

    def test_recommendations_for_common(self):
        """Common passwords should get specific recommendations."""
        result = analyze_password(common_pw)
        common_recs = [r for r in result.recommendations if "common" in r.lower()]
        assert len(common_recs) > 0

    def test_recommendations_for_sequential(self):
        """Sequential passwords should get sequential pattern recommendations."""
        result = analyze_password(sequential)
        seq_recs = [r for r in result.recommendations if "sequential" in r.lower()]
        assert len(seq_recs) > 0

    def test_deterministic_results(self):
        """Same password should always produce same results."""
        result1 = analyze_password(mixed_password)
        result2 = analyze_password(mixed_password)
        assert result1.score == result2.score
        assert result1.strength == result2.strength
        assert result1.entropy == result2.entropy

    def test_score_bounds(self):
        """Scores should always be between 0 and 100."""
        test_passwords = [
            very_short_password,
            common_pw,
            numbers_only,
            lowercase_only,
            uppercase_only,
            mixed_password,
            long_passphrase,
            repeated_chars,
            sequential,
            special_chars,
            empty_input,
        ]
        for pw in test_passwords:
            result = analyze_password(pw)
            assert 0 <= result.score <= 100, f"Score out of bounds for {pw!r}: {result.score}"
            assert result.strength in (
                "Very Weak",
                "Weak",
                "Moderate",
                "Strong",
                "Very Strong",
            ), f"Invalid strength for {pw!r}: {result.strength}"


class TestEntropy:
    """Tests for entropy estimation module."""

    def test_entropy_positive(self):
        """Entropy should be positive for non-empty passwords."""
        result = calculate_entropy(8, {"lowercase": True, "uppercase": True, "digits": True, "special": True})
        assert result > 0

    def test_entropy_lowercase_only(self):
        """Lowercase-only entropy calculation."""
        result = calculate_entropy(8, {"lowercase": True, "uppercase": False, "digits": False, "special": False})
        assert result > 0
        # 8 * log2(26) ≈ 8 * 4.7 = 37.6

    def test_entropy_full_set(self):
        """Full character set entropy should be highest."""
        result = calculate_entropy(8, {"lowercase": True, "uppercase": True, "digits": True, "special": True})
        # 8 * log2(26+26+10+32) = 8 * log2(72) ≈ 8 * 6.17 = 49.4
        assert result > 40

    def test_entropy_empty(self):
        """Entropy should be 0 for empty password."""
        result = calculate_entropy(0, {"lowercase": False, "uppercase": False, "digits": False, "special": False})
        assert result == 0.0

    def test_entropy_to_bits_display(self):
        """Entropy display should work."""
        assert entropy_to_bits_display(0) == "0 bits (no entropy)"
        assert entropy_to_bits_display(15) != ""
        assert entropy_to_bits_display(100) != ""

    def test_search_space_display(self):
        """Search space display should work."""
        assert search_space_display(0) == "0 (no search space)"
        assert search_space_display(10 ** 6) != ""
        assert search_space_display(10 ** 15) != ""


class TestPatternDetection:
    """Tests for pattern detection module."""

    def test_repeated_chars_detection(self):
        """Repeated characters should be detected."""
        result = detect_patterns("aaaaaaaa")
        assert len(result.repeated) > 0

    def test_repeated_chars_3_plus(self):
        """Repeated character runs of 3+ should be detected."""
        result = detect_patterns("aaa")
        assert len(result.repeated) > 0

    def test_no_repeated_short(self):
        """Short repeated runs (< 3) should not be flagged."""
        result = detect_patterns("aa")
        assert len(result.repeated) == 0

    def test_sequential_detection(self):
        """Sequential patterns should be detected."""
        result = detect_patterns("123456")
        assert len(result.sequential) > 0

    def test_known_sequences(self):
        """Known sequential patterns should be found."""
        result = detect_patterns("qwerty")
        assert len(result.sequential) > 0

    def test_no_sequences_random(self):
        """Random-looking passwords should have few sequences."""
        result = detect_patterns("xY7$kP")
        # Should have minimal sequential patterns
        assert len(result.sequential) < 3


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_single_character(self):
        """Single character password analysis."""
        result = analyze_password("a")
        assert result.length == 1
        assert result.strength == "Very Weak"

    def test_exactly_eight(self):
        """Password of exactly 8 characters."""
        result = analyze_password("Abc123!x")
        assert result.length == 8

    def test_seventeen_chars(self):
        """Password of 16 characters."""
        result = analyze_password("Aa1!!Aa1!!Aa1!!A")  # exactly 16 chars
        assert result.length == 16

    def test_very_long_password(self):
        """Very long password should be evaluated correctly."""
        long_pw = "thisisaverylongpasswordthatexceedsallexpectations"
        result = analyze_password(long_pw)
        assert result.length > 30
        assert result.length_analysis["assessment"] in ("Good", "Excellent")

    def test_unicode_handling(self):
        """Password with non-ASCII characters."""
        # This tests that islower/isupper/isdigit handling works
        result = analyze_password("héllo")
        assert result.length > 0

    def test_special_chars_variety(self):
        """Different special characters should be detected."""
        result = analyze_password("@#$%")
        assert result.char_diversity["special"] is True