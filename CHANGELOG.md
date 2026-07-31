# Changelog

Notable changes to SecureScan are documented in this file. The structure is
inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses semantic application versions.

## [1.0.0] - 2026-07-31

### Added

- Flask dashboard for authorized, single-target network assessments.
- Controlled Nmap integration using a fixed profile against the top 100 TCP
  ports with light service-version detection.
- Target validation and an explicit authorization acknowledgement before scan
  execution.
- Transparent, deterministic rule-based findings with severity, confidence,
  evidence, and remediation guidance.
- SQLite persistence for scans, discovered open ports, and findings.
- Historical scan listing and saved assessment detail views that do not rerun
  Nmap or the analyzer.
- Professional HTML reports and in-memory PDF reports generated from stored
  assessment data.
- Individual scan deletion and clear-history workflows with a reusable custom
  confirmation modal.
- Multi-stage Docker and Gunicorn deployment with a non-root runtime user,
  localhost-only published port, persistent database volume, and process health
  endpoint.
- Automated unit, route, persistence, reporting, PDF, and Docker-configuration
  tests with scanner execution mocked.
- GitHub Actions CI covering Python 3.11 through 3.13, compilation, Compose
  validation, and the Docker test-stage image.
- Contribution guidance, pull-request checklist, and structured bug-report and
  feature-request templates.
- Professional README documentation, architecture diagram, and sanitized
  portfolio screenshots using localhost or synthetic demonstration data.

### Security

- Restricted use to systems the user owns or is explicitly authorized to
  assess, with a required acknowledgement before scanning.
- Preserved a fixed single-target scanner profile with no arbitrary Nmap
  arguments, UDP scanning, authenticated checks, or exploitation.
- Kept automated scanner calls mocked; CI performs no real Nmap scans and uses
  only synthetic non-production secrets and temporary database storage.
- Excluded secrets, local environment files, databases, generated reports,
  logs, caches, and private assessment data from version control.
- Generated historical views and reports exclusively from stored data without
  triggering new network activity.

### Changed

- Aligned visible application version wording and Docker image naming with the
  `1.0.0` application release.
- Established a single authoritative application-version constant exposed to
  Flask templates.
- Clarified that report-format version `1.0` identifies the report schema and
  layout independently of application version `1.0.0`.
- Replaced phase-era portfolio wording with release-oriented documentation.

### Known Limitations

- Scans only the top 100 TCP ports; UDP ports are not assessed.
- Does not perform authenticated security checks or exploitation.
- Does not query an external CVE or threat-intelligence source.
- Rule-based findings indicate potential exposure or configuration risk and do
  not prove exploitability or complete security.
- Service detection depends on the limited information returned by Nmap.
- The health endpoint checks process responsiveness only, not database writes,
  Nmap availability, scanner permissions, or target reachability.
- Docker Desktop uses virtualized networking: `localhost` inside the container
  refers to the container, while `host.docker.internal` refers to the host.
  Firewalls, VPNs, and endpoint-security tools can also affect connectivity.
