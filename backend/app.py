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
import re
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file, jsonify

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
from reports import build_report_context, generate_pdf_report
from database.db import (
    initialize_database,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    delete_scan,
    clear_scan_history,
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


def _env_flag(name: str, default: bool = False) -> bool:
    """Parse an opt-in boolean environment variable using explicit true values."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _local_port() -> int:
    """Return a validated local development port with a safe fallback."""
    try:
        port = int(os.environ.get("SECURESCAN_PORT", "5000"))
    except (TypeError, ValueError):
        return 5000
    return port if 1 <= port <= 65535 else 5000


@app.route("/health", methods=["GET"])
def health():
    """Return process health without database, scanner, or analyzer activity."""
    return jsonify(status="healthy", service="securescan"), 200


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
            saved_scan_id = None
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
                recent_scans=recent_scans,
                saved_scan_id=saved_scan_id,
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


def _safe_report_filename(target: str, scan_id: int) -> str:
    """Build a bounded filename containing only safe portable characters."""
    safe_target = re.sub(r"[^A-Za-z0-9_-]+", "-", str(target or "target"))
    safe_target = safe_target.strip("-_")[:80] or "target"
    return f"securescan-report-{safe_target}-{scan_id}.pdf"


@app.route("/scans/<int:scan_id>/report.pdf", methods=["GET"])
def download_scan_report(scan_id: int):
    """Generate an in-memory PDF from an existing saved scan record."""
    db_path = _get_active_db_path()
    try:
        scan = get_scan_by_id(scan_id, db_path=db_path)
    except DatabaseError as de:
        logger.error(f"Database error fetching scan ID {scan_id} for PDF report: {de}")
        abort(500)

    if not scan:
        logger.warning(f"Requested PDF report for missing scan ID {scan_id}.")
        abort(404)

    try:
        report = build_report_context(scan)
        pdf_bytes = generate_pdf_report(report)
    except Exception as error:
        logger.exception(f"PDF report generation failed for scan ID {scan_id}: {error}")
        abort(500, description="The PDF report could not be generated.")

    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=_safe_report_filename(scan.get("target", ""), scan_id),
    )


@app.route("/scans/<int:scan_id>/delete", methods=["POST"])
def delete_scan_route(scan_id: int):
    """
    Scan Deletion Handler ('/scans/<scan_id>/delete')
    Deletes a saved scan record from SQLite via HTTP POST.
    Cascade-deletes related ports and findings, then redirects to dashboard.
    """
    db_path = _get_active_db_path()
    if request.form.get("confirmed") != "1":
        return render_template(
            "confirm_destructive_action.html",
            title="Delete Saved Scan",
            message="Delete this saved scan record?",
            supporting_text="This cannot be undone.",
            action_label="Delete Scan",
            action_url=url_for("delete_scan_route", scan_id=scan_id),
        )

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


@app.route("/scans/clear", methods=["POST"])
def clear_scan_history_route():
    """Delete all saved scan records after explicit confirmation."""
    if request.form.get("confirmed") != "1":
        return render_template(
            "confirm_destructive_action.html",
            title="Clear Scan History",
            message="Delete all saved scan records?",
            supporting_text="This cannot be undone.",
            action_label="Clear History",
            action_url=url_for("clear_scan_history_route"),
        )

    db_path = _get_active_db_path()
    try:
        deleted_count = clear_scan_history(db_path=db_path)
        if deleted_count:
            flash("All saved scan records were deleted.", "success")
        else:
            flash("Scan history is already empty.", "info")
    except DatabaseError:
        logger.exception("Failed to clear saved scan history.")
        flash("Scan history could not be cleared. Please try again.", "error")

    return redirect(url_for("home"))


if __name__ == "__main__":
    # Local development only. Container deployments use Gunicorn instead.
    app.run(
        host=os.environ.get("SECURESCAN_HOST", "127.0.0.1"),
        port=_local_port(),
        debug=_env_flag("SECURESCAN_DEBUG"),
    )
