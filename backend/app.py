import os
from flask import Flask, render_template

# =============================================================================
# SecureScan - Automated Vulnerability Assessment Platform
# Application Entry Point: backend/app.py
# 
# PURPOSE:
# Initializes the Flask web application, configures template and static asset
# file paths, and defines HTTP route handlers to render the user interface.
# 
# BEGINNER NOTE:
# Since app.py is located inside the 'backend' folder, we explicitly set 
# template_folder and static_folder relative to the project root directory
# so Flask can locate templates/index.html and static/css/style.css.
# =============================================================================

# Calculate the absolute path to the root project directory (one level up from backend/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

# Initialize Flask application with explicit template and static folder locations
app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)

@app.route("/")
def home():
    """
    Home Route Handler ('/')
    Renders the main cybersecurity operations dashboard template (index.html).
    Flask's render_template() function compiles the Jinja2 template into standard
    HTML and sends it to the user's browser.
    """
    return render_template("index.html")

if __name__ == "__main__":
    # Run Flask development server on http://127.0.0.1:5000 with debug mode enabled
    app.run(debug=True)