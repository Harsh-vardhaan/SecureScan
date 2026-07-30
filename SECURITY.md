# Security Policy

## Responsible Disclosure

Please report suspected security vulnerabilities privately and allow reasonable
time for investigation before publishing technical details. Do not open a
public issue containing exploit instructions, secrets, personal data, or
information that could put other users at risk.

Use the repository's private GitHub security reporting channel, when available,
to submit:

- A concise description of the issue
- The affected component and version or commit
- Reproduction steps using synthetic or locally controlled data
- The expected and observed behavior
- The potential security impact
- A suggested mitigation, if known

If private GitHub reporting is unavailable, contact the repository owner through
their GitHub profile and request a private disclosure channel. Please do not
include sensitive vulnerability details in the initial public message.

## Authorized-Use Notice

SecureScan is intended only for systems that you own or are explicitly
authorized to assess. Permission should define the target, timing, permitted
techniques, and responsible contact.

Do not use SecureScan to probe third-party systems without explicit permission.
The presence of a publicly reachable host does not constitute authorization.

## Assessment Scope

The current scanner uses a fixed Nmap profile:

```text
-sV --top-ports 100 --version-light -T3
```

SecureScan:

- Accepts one validated host at a time
- Scans the top 100 TCP ports
- Performs limited service-version detection
- Applies local, deterministic rules to observed services
- Stores scan results and findings in SQLite
- Generates HTML and PDF reports from stored scan data

SecureScan does not:

- Perform UDP scanning
- Perform authenticated security checks
- Exploit detected services
- Prove that a finding is exploitable
- Query an external CVE or threat-intelligence database
- Provide a comprehensive security assessment

Rule-based findings indicate potential exposure or configuration risk and
require appropriate manual validation.

## No-Exploitation Policy

Vulnerability reports for this repository must not use destructive testing,
service disruption, persistence, credential theft, data exfiltration, or
exploitation of systems that the reporter does not own.

Use the minimum activity required to demonstrate an issue. Stop testing if it
could affect other users, corrupt data, degrade availability, or cross an agreed
authorization boundary.

## Reporting Vulnerabilities

Reports about the application itself are welcome, including issues involving:

- Target-validation bypasses
- Unexpected command or argument injection
- Unauthorized network activity
- Secret or sensitive-data exposure
- Unsafe report rendering
- Path or file handling
- Database integrity or isolation
- Container privilege or deployment configuration
- Authorization-control bypasses

Operational scan results for unrelated third-party systems are not application
vulnerability reports and must not be submitted to this repository.

## Safe Testing Recommendations

- Test only in an isolated lab or against a host you control.
- Prefer loopback addresses, disposable virtual machines, or synthetic fixtures.
- Keep authorization and scope documented.
- Do not place real credentials or secrets in test inputs.
- Use temporary databases for automated tests.
- Mock scanner calls in unit and route tests.
- Do not run real Nmap scans in continuous integration.
- Use a temporary, non-production `SECRET_KEY` for test processes.
- Never commit `.env` files, SQLite databases, generated reports, logs, or scan
  data containing private infrastructure details.
- Remember that `localhost` inside a Docker container refers to the container.
  On Docker Desktop, `host.docker.internal` refers to the host system.

## Deployment Notes

The `/health` endpoint confirms process responsiveness only. It does not verify
database writes, Nmap availability, scanner permissions, or network
reachability.

Container deployments must provide a strong `SECRET_KEY`. The development
fallback key is not suitable for shared, exposed, or production-like use.

SQLite data in Docker is stored in the `securescan-data` named volume. Treat
that volume as assessment data and protect or remove it according to your data
retention requirements.
