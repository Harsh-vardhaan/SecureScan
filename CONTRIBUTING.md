# Contributing to SecureScan

SecureScan is a cybersecurity portfolio project for authorized, bounded network
service discovery, transparent rule-based analysis, saved assessment history,
and HTML and PDF reporting. Contributions should improve those capabilities
without weakening the project's safety boundaries.

## Authorized and Legal Use

Test SecureScan only against systems you own or are explicitly authorized to
assess. Authorization should define the target, timing, and permitted activity.
Never use project development or issue reproduction as justification for
probing an unrelated or unauthorized system.

SecureScan is limited to one validated target, the top 100 TCP ports, light
service-version detection, and local rule-based observations. Changes must not
silently add UDP scanning, exploitation, arbitrary Nmap arguments, external
target discovery, or claims of proven exploitability.

## Local Setup

Use Python 3.11 or newer and install Nmap separately only when performing an
explicitly authorized local manual assessment. Nmap is not required to run the
mocked unit suite.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
$env:SECRET_KEY = 'local-development-only-change-me'
```

On macOS or Linux, activate the environment with
`source .venv/bin/activate`.

## Branches

Create a focused branch from the current integration branch. Use a short,
descriptive name such as `feature/report-accessibility`,
`fix/target-validation`, or `docs/setup-guidance`. Keep unrelated changes in
separate branches and pull requests.

## Testing

Run the safe test and compilation checks before opening a pull request:

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m compileall backend scanner vulnerability database reports
git diff --check
```

Tests that exercise Flask scan behavior must mock the scanner entry point.
Automated tests and CI must never invoke Nmap, contact a scan target, call the
application scan route with a real scanner, or depend on private infrastructure.
Use synthetic fixtures and temporary databases.

If Docker-related files change, also validate the test configuration:

```powershell
$env:SECRET_KEY = 'ci-only-synthetic-secret-not-for-production'
docker compose config --quiet
docker build --target test -t securescan:test .
docker run --rm -e SECRET_KEY=ci-only-synthetic-secret-not-for-production securescan:test
```

Do not use `docker compose up` as part of automated verification.

## Pull Requests

- Explain the problem, scope, and security impact of the change.
- Keep changes focused and preserve the fixed scanner boundaries.
- Add or update tests for changed behavior, with scanner calls mocked.
- Update documentation when commands, behavior, or limitations change.
- Sanitize screenshots and logs before attaching them.
- Confirm that no real or unauthorized scan was performed.
- Ensure the working tree contains no generated or private artifacts.

Never commit secrets, `.env` files, SQLite databases, generated reports, logs,
caches, virtual environments, or real target data. Use placeholders and
synthetic examples only.

## Security Issues

Do not disclose vulnerabilities or sensitive reproduction details in a public
issue. Follow the private reporting guidance in [SECURITY.md](SECURITY.md).
