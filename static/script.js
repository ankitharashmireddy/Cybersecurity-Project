// Password Strength Checker - Client-Side Script
// Handles show/hide password, form submission, and UI updates.
// Communicates with Flask backend via POST /analyze.

document.addEventListener("DOMContentLoaded", function () {
  // Elements
  const passwordInput = document.getElementById("password");
  const showHideBtn = document.querySelector(".show-hide-btn");
  const strengthBar = document.querySelector(".strength-bar");
  const strengthLabel = document.querySelector(".strength-label");
  const form = document.querySelector(".form-section form");
  const resultSection = document.querySelector(".result-section");
  const analyzeBtn = form.querySelector(".btn-analyze");

  // Show/hide password toggle
  if (showHideBtn && passwordInput) {
    showHideBtn.addEventListener("click", function () {
      const type =
        passwordInput.getAttribute("type") === "password" ? "text" : "password";
      passwordInput.setAttribute("type", type);

      // Update button text/aria state
      const isPassword = type === "password";
      showHideBtn.setAttribute("aria-pressed", !isPassword);
      showHideBtn.textContent = isPassword ? "Hide" : "Show";
    });
  }

  // Form submission
  if (form) {
    form.addEventListener("submit", function (event) {
      // Prevent default form submission
      event.preventDefault();

      const password = passwordInput.value;

      // Input validation
      if (!password || password.trim() === "") {
        showResults({
          strength: "Very Weak",
          score: 0,
          length: 0,
          length_assessment: "No password provided",
          lowercase: false,
          uppercase: false,
          digits: false,
          special: false,
          charset_found: 0,
          common_password: false,
          repeated_patterns: [],
          sequential_patterns: [],
          entropy: 0.0,
          search_space: 0,
          recommendations: [
            "Enter a password to evaluate its strength",
            "Use at least 8 characters for basic security",
          ],
        });
        return;
      }

      // Show loading state
      analyzeBtn.disabled = true;
      analyzeBtn.textContent = "Analyzing...";

      // Send password to Flask backend
      fetch("/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          password: password,
        }),
      })
        .then((response) => {
          if (!response.ok) {
            throw new Error("Analysis failed");
          }
          return response.json();
        })
        .then((data) => {
          // data.results contains the analysis, password is NOT included
          showResults(data.results);
        })
        .catch((error) => {
          console.error("Error:", error);
          showResults({
            strength: "Very Weak",
            score: 0,
            length: 0,
            length_assessment: "Analysis unavailable",
            lowercase: false,
            uppercase: false,
            digits: false,
            special: false,
            charset_found: 0,
            common_password: false,
            repeated_patterns: [],
            sequential_patterns: [],
            entropy: 0.0,
            search_space: 0,
            recommendations: [
              "Unable to analyze password. Please try again.",
            ],
          });
        })
        .finally(() => {
          // Reset button state
          analyzeBtn.disabled = false;
          analyzeBtn.textContent = "Analyze Password";
        });
    });
  }

  // Show results in UI
  function showResults(results) {
    // Update strength indicator
    updateStrengthIndicator(results.strength, results.score);

    // Update character composition
    updateCharComposition(
      results.lowercase,
      results.uppercase,
      results.digits,
      results.special,
      results.charset_found
    );

    // Update patterns
    updatePatterns(
      results.repeated_patterns,
      results.sequential_patterns
    );

    // Update entropy and search space
    updateEntropy(results.entropy);
    updateSearchSpace(results.search_space);

    // Update recommendations
    updateRecommendations(results.recommendations);

    // Show the result section
    resultSection.classList.remove("hidden");
  }

  // Update strength indicator
  function updateStrengthIndicator(strength, score) {
    // Map strength to CSS class
    const strengthClasses = {
      "Very Weak": "very-weak",
      "Weak": "weak",
      "Moderate": "moderate",
      "Strong": "strong",
      "Very Strong": "very-strong",
    };

    // Remove existing classes
    if (strengthBar) {
      Object.keys(strengthClasses).forEach((cls) => {
        strengthBar.classList.remove(cls);
      });
    }

    // Add correct class
    if (strengthBar && strengthLabel) {
      strengthBar.classList.add(strengthClasses[strength] || "very-weak");
      strengthLabel.textContent = strength;
      strengthLabel.style.color =
        strength === "Very Strong"
          ? "var(--accent-very-strong)"
          : strength === "Strong"
          ? "var(--accent-strong)"
          : strength === "Moderate"
          ? "var(--accent-moderate)"
          : "#e74c3c";
    }

    // Update score display - score is in the result element
    const scoreElement = document.querySelector(
      '.strength-indicator .score'
    );
    if (scoreElement) {
      scoreElement.textContent = `${score}/100`;
    }
  }

  // Update character composition
  function updateCharComposition(lowercase, uppercase, digits, special, charsetFound) {
    const charRows = document.querySelectorAll(".char-row");

    if (charRows.length >= 4) {
      const rows = [
        { label: "lowercase", value: lowercase, element: charRows[0] },
        { label: "uppercase", value: uppercase, element: charRows[1] },
        { label: "digits", value: digits, element: charRows[2] },
        { label: "special", value: special, element: charRows[3] },
      ];

      rows.forEach((row) => {
        const charYes = row.element.querySelector(".char-yes");
        const charNo = row.element.querySelector(".char-no");

        if (charYes && charNo) {
          if (row.value) {
            charYes.style.display = "inline";
            charNo.style.display = "none";
          } else {
            charYes.style.display = "none";
            charNo.style.display = "inline";
          }
        }
      });
    }
  }

  // Update patterns
  function updatePatterns(repeatedPatterns, sequentialPatterns) {
    const patternsList = document.querySelector(".patterns-list");
    if (!patternsList) return;

    // Clear existing
    patternsList.innerHTML = "";

    // Add repeated patterns
    if (repeatedPatterns && repeatedPatterns.length > 0) {
      repeatedPatterns.forEach((pattern) => {
        const li = document.createElement("li");
        li.textContent = `Repeated: ${pattern}`;
        patternsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "No repeated patterns detected";
      li.style.color = "var(--accent-strong)";
      patternsList.appendChild(li);
    }

    // Add sequential patterns
    if (sequentialPatterns && sequentialPatterns.length > 0) {
      sequentialPatterns.forEach((pattern) => {
        const li = document.createElement("li");
        li.textContent = `Sequential: ${pattern}`;
        patternsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "No sequential patterns detected";
      li.style.color = "var(--accent-strong)";
      patternsList.appendChild(li);
    }
  }

  // Update entropy display
  function updateEntropy(entropy) {
    const entropyElement = document.querySelector(".entropy-value");
    if (entropyElement) {
      entropyElement.textContent = entropy.toFixed(1) + " bits";
    }
  }

  // Update search space display
  function updateSearchSpace(searchSpace) {
    const searchSpaceElement = document.querySelector(".search-space-value");
    if (searchSpaceElement) {
      if (searchSpace > 0) {
        searchSpaceElement.textContent = `${searchSpace.toLocaleString()} possibilities`;
      } else {
        searchSpaceElement.textContent = "0 possibilities";
      }
    }
  }

  // Update recommendations
  function updateRecommendations(recommendations) {
    const recList = document.querySelector(".recommendations-list");
    if (!recList) return;

    // Clear existing
    recList.innerHTML = "";

    // Add each recommendation
    recommendations.forEach((rec) => {
      const li = document.createElement("li");
      li.textContent = rec;
      recList.appendChild(li);
    });
  }
});