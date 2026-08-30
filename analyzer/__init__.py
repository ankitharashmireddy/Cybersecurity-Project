# Password Strength Checker - Analyzer Package
# Core password analysis engine for security evaluation

"""Password strength analysis module.

Provides comprehensive password strength evaluation including:
- Strength classification
- Length analysis
- Character diversity analysis
- Common password detection
- Pattern detection (repeated and sequential)
- Entropy estimation
- Search space estimation
- Security recommendations

This module processes passwords locally and does not send data to external services.
"""

__version__ = "1.0.0"

# Re-export commonly used functions for convenient importing
from analyzer.password_analyzer import analyze_password  # noqa: F401
from analyzer.pattern_checker import detect_patterns  # noqa: F401
from analyzer.entropy import calculate_entropy, entropy_to_bits_display, search_space_display  # noqa: F401