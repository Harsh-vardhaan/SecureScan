# SecureScan

## Docker deployment foundation

SecureScan requires Docker Desktop on Windows with Linux containers enabled.
The image installs both the Python `python-nmap` wrapper and the Linux Nmap
executable. Scanning must only be performed against systems you own or have
explicit authorization to assess.

SecureScan requires a strong Flask session secret. Environment variables set in
PowerShell do not persist into a new PowerShell session, so set `SECRET_KEY`
again whenever you open a new session before using Compose:

```powershell
$env:SECRET_KEY = '<generate-a-long-random-value>'
docker compose up --build -d
```

Alternatively, create a local Compose environment file from the safe placeholder:

```powershell
Copy-Item .env.example .env
# Edit .env and replace the placeholder with a strong random value.
docker compose up --build -d
```

The local `.env` file contains a secret, is ignored by Git, and must never be
committed. The committed `.env.example` contains only a placeholder.

Open the application at `http://127.0.0.1:5001` and check process health at
`http://127.0.0.1:5001/health`. Host port 5001 avoids a common Windows port-5000
conflict; Gunicorn continues to listen on port 5000 inside the container.

Stop the service without removing saved scan history:

```powershell
docker compose down
```

SQLite data is stored in the named `securescan-data` volume and survives normal
container recreation. Running `docker compose down -v` permanently deletes that
volume and its saved database.

Inside the Linux container, `localhost` refers to the container itself. Use
`host.docker.internal` to address the Windows host. Docker Desktop uses
virtualized networking, so reachability and scan results can differ from scans
performed directly on native Windows or Linux. Windows firewall, VPN, and
endpoint-security rules may also affect results.
