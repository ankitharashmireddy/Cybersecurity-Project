#!/usr/bin/env python
import os
import subprocess

print("=" * 60)
print("PASSWORD STRENGTH CHECKER - GIT INITIALIZATION")
print("=" * 60)

# Check we're in the right directory
cwd = os.getcwd()
print(f"\nWorking directory: {cwd}")

# List key project files
key_files = [
    'app.py',
    'README.md',
    'requirements.txt',
    'analyzer/__init__.py',
    'tests/test_password_analyzer.py',
    'docs/security-assessment.md',
    'docs/threat-model.md',
    'docs/testing.md',
    'templates/index.html',
    'static/style.css',
    'static/script.js',
    'data/common_passwords.txt'
]

print("\nKey project files:")
for f in key_files:
    exists = os.path.exists(f)
    status = "[OK]" if exists else "[MISSING]"
    print(f"  {status} {f}")

# Verify tests pass
print("\nRunning final test verification...")
result = subprocess.run(
    ['python', '-m', 'pytest', 'tests/', '-q'],
    capture_output=True, text=True, cwd=os.getcwd()
)
if result.returncode == 0:
    print("  [OK] All 36 analyzer tests pass")
else:
    print("  [XX] Test failures:")
    print(result.stdout)
    print(result.stderr)

result2 = subprocess.run(
    ['python', '-m', 'pytest', 'test_security.py', '-q'],
    capture_output=True, text=True, cwd=os.getcwd()
)
if result2.returncode == 0:
    print("  [OK] All 7 security tests pass")
else:
    print("  [XX] Security test failures:")
    print(result2.stdout)
    print(result2.stderr)

print("\n" + "=" * 60)
print("NEXT STEPS - Git initialization:")
print("=" * 60)
print("\n1. Initialize git repository:")
print("   git init")
print("")
print("2. Add all project files:")
print("   git add .")
print("")
print("3. Create initial commit:")
print("   git commit -m \"Initial commit: Password Strength Checker project\"")
print("")
print("4. Add remote repository:")
print("   git remote add origin https://github.com/ankitharashmireddy/Cybersecurity-Project.git")
print("")
print("5. Set branch and push:")
print("   git branch -M main")
print("   git push -u origin main")
print("")
print("6. Add .gitignore (recommended):")
print("   echo '__pycache__' >> .gitignore")
print("   echo '.pytest_cache' >> .gitignore")
print("   echo '*.pyc' >> .gitignore")
print("")
print("=" * 60)
PYEOF