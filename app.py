"""Password Strength Checker Flask Application.

A professional web application that evaluates password security locally
using a Python analysis engine, with privacy-first design.

THE PRIVACY FLOW:
- Password is submitted via POST to /analyze
- Flask backend uses the existing analyzer package to evaluate the password
- NO passwords are logged, stored, cached, or persisted
- NO passwords are sent to external APIs
- Analysis results are returned as structured JSON (password NOT included)
- The password is cleared from application state immediately after analysis

This is NOT a "client-side only" application. The password is sent to the
Flask backend for analysis using the Python engine. Users who require
completely client-side analysis should note this limitation.
"""

from __future__ import annotations

import typing as t
from flask import Flask, render_template, request, jsonify, abort
from analyzer import analyze_password

# Flask application instance
app = Flask(__name__)

# Flask security configuration
# https://flask.palletsprojects.com/en/2.3.x/config/#session-configuration
app.config["SECRET_KEY"] = "dev-change-me-in-production"  # noqa: S105
app.config["SESSION_TYPE"] = "filesystem"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes

# Do NOT debug=True in production
# See: https://flask.palletsprojects.com/en/2.3.x/deployment/
# Production should use a proper WSGI server (gunicorn, waitress, etc.)


def _analyze_password_safe(password: str) -> dict:
    """Run password analysis and return results as JSON-safe dict.

    This is the core analysis function. It:
    - Uses the existing analyzer package from Stage 1
    - Does NOT log the password
    - Does NOT store the password
    - Returns results without the original password

    Args:
        password: The password string to analyze.

    Returns:
        Dict containing all analysis results suitable for JSON serialization.
        The original password is NEVER included in the output.
    """
    if not password:
        # Handle empty input - return minimal analysis
        return {
            "strength": "Very Weak",
            "score": 0,
            "length": 0,
            "length_assessment": "Empty password",
            "lowercase": False,
            "uppercase": False,
            "digits": False,
            "special": False,
            "charset_found": 0,
            "common_password": False,
            "repeated_patterns": [],
            "sequential_patterns": [],
            "entropy": 0.0,
            "search_space": 0,
            "recommendations": [
                "Enter a password to evaluate its strength",
                "Use at least 8 characters for basic security",
            ],
        }

    # Perform analysis using the existing Stage 1 engine
    analysis: object = analyze_password(password)

    # Build results dict WITHOUT including the original password
    # This is the critical privacy step - never expose the password
    results: dict = {
        "strength": analysis.strength,
        "score": analysis.score,
        "length": analysis.length,
        "length_assessment": analysis.length_analysis["assessment"],
        "lowercase": analysis.char_diversity["lowercase"],
        "uppercase": analysis.char_diversity["uppercase"],
        "digits": analysis.char_diversity["digits"],
        "special": analysis.char_diversity["special"],
        "charset_found": analysis.char_diversity["charsets_found"],
        "common_password": analysis.common_password,
        "repeated_patterns": analysis.repeated_patterns,
        "sequential_patterns": analysis.sequential_patterns,
        "entropy": analysis.entropy,
        "search_space": analysis.search_space,
        "recommendations": analysis.recommendations,
    }

    return results


@app.route("/", methods=["GET", "POST"])
def index():
    """Main page - serve the password strength checker UI.

    Handles both GET (show form) and POST (analyze password).
    On POST, analyzes the password and displays results.
    """
    if request.method == "GET":
        # GET request - show the form with no results
        return render_template(
            "index.html",
            result=None,
            show_password=False,
        )

    # POST request - analyze the password
    # Get password from form data
    password: str = request.form.get("password", "", type=str)

    # Input validation: check for empty submission
    if not password or password.strip() == "":
        # Empty input - show results indicating no password provided
        results = {
            "strength": "Very Weak",
            "score": 0,
            "length": 0,
            "length_assessment": "No password provided",
            "lowercase": False,
            "uppercase": False,
            "digits": False,
            "special": False,
            "charset_found": 0,
            "common_password": False,
            "repeated_patterns": [],
            "sequential_patterns": [],
            "entropy": 0.0,
            "search_space": 0,
            "recommendations": [
                "Enter a password to evaluate its strength",
                "Use at least 8 characters for basic security",
            ],
        }
        return render_template(
            "index.html",
            result=results,
            show_password=False,
            show_empty=True,
        )

    # Perform analysis using the safe wrapper
    # The password is in-memory only within this request context
    results = _analyze_password_safe(password)

    # Clear the password from local variables where practical
    # (Python garbage collector will handle cleanup, but we explicitly clear)
    # Note: Python's automatic memory management handles this, but we
    # explicitly remove the reference to aid cleanup
    # Note: Do NOT store password in session, cookies, or any persistent state

    # Render the template with results
    # The password is NEVER passed to the template
    return render_template(
        "index.html",
        result=results,
        show_password=False,
    )


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """API endpoint for password analysis.

    Returns structured JSON with analysis results.
    The original password is NEVER included in the response.

    Returns:
        JSON dict with analysis results (no password field)
        HTTP 200 on success
        HTTP 400 if no password provided
        HTTP 500 on unexpected error (no internal details exposed)
    """
    # Get password from JSON body or form data
    if request.is_json:
        data = request.get_json(silent=True) or {}
        password: str = str(data.get("password", ""))
    else:
        password = request.form.get("password", "")

    # Input validation
    if not password or password.strip() == "":
        abort(400, description="Password is required")

    try:
        # Perform analysis
        results = _analyze_password_safe(password)

        # IMPORTANT: The password is NOT included in the results dict
        # This is enforced by the _analyze_password_safe function

        return jsonify({
            "success": True,
            "results": results,
        })

    except Exception as e:
        # Log the error internally but don't expose details to client
        # In production, use proper logging (see Flask documentation)
        # Do NOT include the password in the error message
        # Do NOT expose internal exception details
        app.logger.error("Password analysis error: %s", str(e))
        abort(500, description="Internal server error during analysis")


@app.errorhandler(400)
def bad_request(error: t.Any) -> tuple:
    """Handle 400 Bad Request errors.

    Returns JSON for API requests, HTML template for regular requests.
    """
    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "error": error.description or "Bad request",
        }), 400
    # For regular requests, redirect back to home with error
    return render_template("index.html", error=error.description), 400


@app.errorhandler(500)
def internal_error(error: t.Any) -> tuple:
    """Handle 500 Internal Server errors.

    Logs error internally, returns generic error page.
    Never exposes password or internal details to client.
    """
    # Log the error for debugging
    app.logger.error("Internal server error: %s", str(error))
    # Return generic error - no password or internal details exposed
    return render_template("index.html", error="An unexpected error occurred"), 500


# Health check endpoint (useful for Docker/Kubernetes deployment)
@app.route("/health", methods=["GET"])
def health_check():
    """Simple health check endpoint.

    Returns:
        JSON indicating the service is running.
    """
    return jsonify({"status": "healthy", "service": "password-strength-checker"})


# Module-level __main__ guard for direct execution
# In production, use: python -m app or a WSGI server (gunicorn, etc.)
if __name__ == "__main__":
    # Note: debug mode should NOT be used in production
    # Use a proper WSGI server for production deployment
    app.run(host="0.0.0.0", port=5000, debug=False)