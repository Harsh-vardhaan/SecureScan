from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h1>🔒 SecureScan</h1>
    <h2>Automated Vulnerability Assessment Platform</h2>
    <p>Welcome to SecureScan!</p>
    <p>Version 0.1</p>
    """

if __name__ == "__main__":
    app.run(debug=True)