# Password Strength Checker

[Security-focused password analysis web application with entropy estimation, pattern detection, common-password detection, security recommendations, and privacy-first local processing.]

## Project Overview

This project was built as a cybersecurity portfolio piece for entry-level application security and penetration testing positions. It demonstrates hands-on development and application security understanding without making false claims about penetration testing, vulnerability discovery, or using security tools that don't naturally belong in a password checker.

The project is intentionally educational and security-focused, suitable for a student portfolio. It does not use Nmap, Metasploit, or Wireshark — those tools don't naturally belong in a Password Strength Checker. Instead, it focuses on password security, application security, secure development, and security testing.

The author is an MCA student specializing in Artificial Intelligence and Machine Learning with a CGPA of 9.41, currently completing Cisco Networking Academy coursework (CyberOps Associate, Network Defense, Cyber Threat Management, Endpoint Security, Python Essentials 2). A related project is a Phishing Email Detection System.

## Problem Statement

Password security is a fundamental concern in application security. Users frequently choose weak passwords, reuse passwords across services, and employ predictable patterns that make accounts vulnerable to compromise. A password strength checker helps users understand the security implications of their password choices and adopt better practices.

## Objectives

- Build a professional, working password strength checker
- Demonstrate understanding of password entropy, search space, and pattern detection
- Provide privacy-first analysis (no passwords sent to external services)
- Create documentation suitable for a technical screening/portfolio
- Avoid unnecessary complexity while delivering meaningful security analysis

## Features

### Core Analysis

- **Strength Classification**: Very Weak → Weak → Moderate → Strong → Very Strong based on a deterministic 0–100 scoring system
- **Length Analysis**: Evaluates password length with contextual assessment (e.g., "Excellent" for 16+ chars, "Adequate" for 8 chars)
- **Character Diversity**: Detects presence of lowercase, uppercase, digits, and special characters; reports charset count and diversity ratio
- **Common Password Detection**: Compares against a local dataset of 48 common/weak passwords; explicitly cannot represent all compromised passwords in real-world breaches
- **Repeated Pattern Detection**: Identifies runs of 3+ identical characters (e.g., `aaaaaaaa`, `11111111`)
- **Sequential Pattern Detection**: Identifies obvious sequences (`123456`, `abcdef`, `qwerty`, ascending/descending consecutive)

### Scoring Methodology (0–100)

| Component | Max Points | Details |
|-----------|-----------|---------|
| **Length** | 35 pts | 16+ chars = 35, 12 = 30, 10 = 25, 8 = 20, 6 = 15, 4 = 10 |
| **Character Diversity** | 35 pts | 1 charset = 9 pts, 2 = 18, 3 = 27, 4 (full) = 35 |
| **Clean Password Bonus** | +10 pts | +10 if no common password, no repeated patterns, no sequential patterns |
| **Max Raw Score** | **80 pts** | 35 + 35 + 10 = 80 |
| **Very Strong threshold** | **>= 80** | Now reachable! |
| **Strong** | >= 60 | |
| **Moderate** | >= 40 | |
| **Weak** | >= 20 | |
| **Very Weak** | < 20 | |

**Penalties** (reduce from raw score):
- Common password: -40 points
- Repeated patterns: up to -25 points
- Sequential patterns: up to -20 points

### Entropy Estimation

Theoretical entropy using: `entropy = password_length × log2(character_set_size)`

- Clearly labeled **"Estimated Theoretical Entropy"**
- Explains this assumes random password generation from the detected character set
- Does **NOT** measure real-world cracking time or breach database presence
- Does **NOT** guarantee cracking time of a user-selected password
- Includes display helpers: `entropy_to_bits_display()` and `search_space_display()`

### Pattern Detection

- **Repeated**: Runs of 3+ identical characters (`aaaaaaaa`, `11111111`)
- **Sequential**: `123456`, `abcdef`, `qwerty`, ascending/descending consecutive character patterns
- All detection is purely syntactic, local-only

### Privacy & Security Design

- **Password never sent to external APIs**: All analysis local to Flask backend
- **Password never stored**: In-memory only; cleared after analysis
- **Password never logged**: Code review confirmed no password logging
- **Password not displayed in results**: The password itself never appears in UI output
- **HTTPS recommended**: Application should be served over HTTPS in production
- **Development-only SECRET_KEY**: Clearly documented as dev fallback
- **Privacy notice in UI**: Explicit notice explaining password handling

### Technology Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, vanilla JavaScript (no frameworks, no CDNs)
- **Testing**: pytest

## Architecture

```
Password-Strength-Checker/
│
├── app.py                 # Flask backend; reuses analyzer package from Stage 1
├── requirements.txt
├── .gitignore
│
├── analyzer/              # Core password analysis engine (Stage 1)
│   ├── __init__.py
│   ├── password_analyzer.py   # Main analysis: length, diversity, patterns, entropy, search space, scoring, recommendations
│   ├── entropy.py               # Entropy estimation with display helpers
│   └── pattern_checker.py     # Repeated and sequential pattern detection
│
├── templates/
│   └── index.html   # Professional, responsive UI; privacy-first design
│
├── static/
│   ├── style.css    # Custom CSS; no external dependencies
│   └── script.js   # Vanilla JS; show/hide password, API communication, UI updates
|
├── data/
│   └── common_passwords.txt  # 48 common passwords; educational-only, not exhaustive
|
└── docs/
    ├── security-assessment.md   # Security assessment of our own application
    ├── threat-model.md          # Assets, trust boundaries, attack surfaces, threats, mitigations
    └── testing.md               # Unit tests, integration tests, security/privacy tests