"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Application Entry Point: backend/app.py

PURPOSE:
Initializes the Flask web application, configures template and static asset
file paths, defines HTTP route handlers for the cybersecurity dashboard,
validates user input, and triggers the scanner engine.
=============================================================================
"""

import os
import sys
import logging
from flask import Flask, render_template, request

# Calculate the absolute path to the root project directory (one level up from backend/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Configure logging for application diagnostics
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize Flask application with explicit template and static folder locations
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

# Import scanner components after setting up Python path
from scanner.validator import validate_target
from scanner.nmap_scanner import (
    run_scan,
    ScannerUnavailableError,
    ScanTimeoutError,
    ScanExecutionError,
)


@app.route("/", methods=["GET", "POST"])
def home():
    """
    Home Route Handler ('/')
    GET:  Renders the cybersecurity operations dashboard template (index.html).
    POST: Processes scan request, verifies user authorization confirmation,
          validates target input, executes Nmap scan, and presents results.
    """
    if request.method == "POST":
        target_input = request.form.get("target", "")
        auth_confirmed = request.form.get("auth_confirmed")

        # 1. Server-side authorization check
        if not auth_confirmed:
            error_msg = "Confirm that you are authorized to scan this target."
            return render_template("index.html", error=error_msg, target=target_input)

        # 2. Target validation & normalization
        is_valid, normalized_target, val_error = validate_target(target_input)
        if not is_valid:
            return render_template("index.html", error=val_error, target=target_input)

        # 3. Scan execution & exception handling
        try:
            logger.info(f"Initiating authorized scan for target: {normalized_target}")
            scan_result = run_scan(normalized_target)
            return render_template("index.html", scan_result=scan_result, target=normalized_target)

        except ScannerUnavailableError as e:
            logger.error(f"Scanner unavailable: {e}")
            return render_template("index.html", error=str(e), target=normalized_target)

        except ScanTimeoutError as e:
            logger.warning(f"Scan timed out for {normalized_target}: {e}")
            error_msg = "The target did not respond to the limited scan within the allowed time."
            return render_template("index.html", error=error_msg, target=normalized_target)

        except ScanExecutionError as e:
            logger.error(f"Scan execution failed for {normalized_target}: {e}")
            error_msg = "The scan could not be completed. Check the server logs for details."
            return render_template("index.html", error=error_msg, target=normalized_target)

        except Exception as e:
            logger.exception(f"Unexpected error processing scan request for {normalized_target}: {e}")
            error_msg = "An unexpected error occurred while executing the scan."
            return render_template("index.html", error=error_msg, target=normalized_target)

    return render_template("index.html")


if __name__ == "__main__":
    # Run Flask development server on http://127.0.0.1:5000 with debug mode enabled
    app.run(debug=True)