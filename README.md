# SecureScan

## Docker deployment foundation

SecureScan requires Docker Desktop on Windows with Linux containers enabled.
The image installs both the Python `python-nmap` wrapper and the Linux Nmap
executable. Scanning must only be performed against systems you own or have
explicit authorization to assess.

Set a strong Flask session secret in PowerShell before starting the service:

```powershell
$env:SECRET_KEY = '<generate-a-long-random-value>'
docker compose up --build -d
```

Open the application at `http://127.0.0.1:5000` and check process health at
`http://127.0.0.1:5000/health`.

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
