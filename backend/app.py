"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Application Entry Point: backend/app.py

PURPOSE:
Initializes the Flask web application, configures template and static asset
file paths, defines HTTP route handlers for the cybersecurity dashboard,
validates user input, triggers the Nmap scanner engine, runs rule-based security
analysis, and persists scan records in SQLite.
=============================================================================
"""

import os
import sys
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, abort

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

# Secret key configuration for Flask flash message session signing
# WARNING: The default 'dev-only-change-me' key is for local development only.
# Set the SECRET_KEY environment variable in production environments.
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

# Import scanner components after setting up Python path
from scanner.validator import validate_target
from scanner.nmap_scanner import (
    run_scan,
    ScannerUnavailableError,
    ScanTimeoutError,
    ScanExecutionError,
)
from vulnerability import analyze_scan
from reports import build_report_context
from database.db import (
    initialize_database,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    delete_scan,
    DatabaseError,
)


def _get_active_db_path() -> str:
    """Helper to retrieve configured database path from app.config or environment."""
    return app.config.get("DATABASE_PATH") or os.environ.get("SECURESCAN_DATABASE_PATH")


def init_app_db():
    """Initialize database tables on Flask startup."""
    try:
        db_path = _get_active_db_path()
        initialize_database(db_path=db_path)
    except Exception as e:
        logger.error(f"Failed to initialize SQLite database on application startup: {e}")


# Initialize database automatically on startup
with app.app_context():
    init_app_db()


@app.route("/", methods=["GET", "POST"])
def home():
    """
    Home Route Handler ('/')
    GET:  Renders the cybersecurity operations dashboard template (index.html)
          populated with recent real scan history from SQLite.
    POST: Processes scan request, verifies user authorization confirmation,
          validates target input, executes Nmap scan, performs security analysis,
          persists findings to SQLite, and presents results.
    """
    db_path = _get_active_db_path()

    if request.method == "POST":
        target_input = request.form.get("target", "")
        auth_confirmed = request.form.get("auth_confirmed")

        # Fetch recent scans for history table rendering
        recent_scans = []
        try:
            recent_scans = get_recent_scans(limit=10, db_path=db_path)
        except Exception as e:
            logger.error(f"Error fetching recent scans for POST rendering: {e}")

        # 1. Server-side authorization check
        if not auth_confirmed:
            error_msg = "Confirm that you are authorized to scan this target."
            return render_template("index.html", error=error_msg, target=target_input, recent_scans=recent_scans)

        # 2. Target validation & normalization
        is_valid, normalized_target, val_error = validate_target(target_input)
        if not is_valid:
            return render_template("index.html", error=val_error, target=target_input, recent_scans=recent_scans)

        # 3. Scan execution & exception handling
        try:
            logger.info(f"Initiating authorized scan for target: {normalized_target}")
            scan_result = run_scan(normalized_target)

            # 4. Rule-based security vulnerability analysis
            analysis_result = None
            analysis_error = None
            try:
                analysis_result = analyze_scan(scan_result)
            except Exception as ae:
                logger.exception(f"Security analysis failed for target {normalized_target}: {ae}")
                analysis_error = "Rule-based security analysis could not be completed for this scan."

            # 5. Persist scan and analysis results into SQLite
            try:
                saved_scan_id = save_scan(scan_result, analysis_result, db_path=db_path)
                logger.info(f"Successfully saved scan ID {saved_scan_id} for target {normalized_target}.")
            except Exception as dbe:
                logger.error(f"Failed to persist scan result to database: {dbe}")
                flash("The scan completed, but the result could not be saved to history.", "warning")

            # Reload recent scans list after saving new scan
            try:
                recent_scans = get_recent_scans(limit=10, db_path=db_path)
            except Exception as e:
                logger.error(f"Error refreshing recent scans: {e}")

            return render_template(
                "index.html",
                scan_result=scan_result,
                analysis_result=analysis_result,
                analysis_error=analysis_error,
                target=normalized_target,
                recent_scans=recent_scans
            )

        except ScannerUnavailableError as e:
            logger.error(f"Scanner unavailable: {e}")
            return render_template("index.html", error=str(e), target=normalized_target, recent_scans=recent_scans)

        except ScanTimeoutError as e:
            logger.warning(f"Scan timed out for {normalized_target}: {e}")
            error_msg = "The target did not respond to the limited scan within the allowed time."
            return render_template("index.html", error=error_msg, target=normalized_target, recent_scans=recent_scans)

        except ScanExecutionError as e:
            logger.error(f"Scan execution failed for {normalized_target}: {e}")
            error_msg = "The scan could not be completed. Check the server logs for details."
            return render_template("index.html", error=error_msg, target=normalized_target, recent_scans=recent_scans)

        except Exception as e:
            logger.exception(f"Unexpected error processing scan request for {normalized_target}: {e}")
            error_msg = "An unexpected error occurred while executing the scan."
            return render_template("index.html", error=error_msg, target=normalized_target, recent_scans=recent_scans)

    # GET Request: Load recent real scans from database
    recent_scans = []
    try:
        recent_scans = get_recent_scans(limit=10, db_path=db_path)
    except Exception as e:
        logger.error(f"Failed to retrieve recent scans for GET /: {e}")

    return render_template("index.html", recent_scans=recent_scans)


@app.route("/scans/<int:scan_id>", methods=["GET"])
def view_scan(scan_id: int):
    """
    Historical Scan Detail Route Handler ('/scans/<scan_id>')
    Retrieves and displays a previously executed scan record from SQLite by ID.
    Does NOT rerun network scans. Returns HTTP 404 if scan ID does not exist.
    """
    db_path = _get_active_db_path()
    try:
        scan = get_scan_by_id(scan_id, db_path=db_path)
        if not scan:
            logger.warning(f"Requested scan ID {scan_id} not found in database.")
            abort(404)
        return render_template("scan_detail.html", scan=scan)
    except DatabaseError as de:
        logger.error(f"Database error fetching scan ID {scan_id}: {de}")
        abort(500)


@app.route("/scans/<int:scan_id>/report", methods=["GET"])
def view_scan_report(scan_id: int):
    """Render an HTML report using only an already-saved scan record."""
    db_path = _get_active_db_path()
    try:
        scan = get_scan_by_id(scan_id, db_path=db_path)
        if not scan:
            logger.warning(f"Requested report for missing scan ID {scan_id}.")
            abort(404)
        report = build_report_context(scan)
        return render_template("report.html", report=report)
    except DatabaseError as de:
        logger.error(f"Database error generating report for scan ID {scan_id}: {de}")
        abort(500)


@app.route("/scans/<int:scan_id>/delete", methods=["POST"])
def delete_scan_route(scan_id: int):
    """
    Scan Deletion Handler ('/scans/<scan_id>/delete')
    Deletes a saved scan record from SQLite via HTTP POST.
    Cascade-deletes related ports and findings, then redirects to dashboard.
    """
    db_path = _get_active_db_path()
    try:
        deleted = delete_scan(scan_id, db_path=db_path)
        if deleted:
            flash(f"Scan #{scan_id} was successfully deleted.", "success")
        else:
            flash(f"Scan #{scan_id} was not found or has already been deleted.", "warning")
    except Exception as e:
        logger.error(f"Failed to delete scan ID {scan_id}: {e}")
        flash(f"An error occurred while deleting scan #{scan_id}.", "error")

    return redirect(url_for("home"))


if __name__ == "__main__":
    # Run Flask development server on http://127.0.0.1:5000 with debug mode enabled
    app.run(debug=True)
