"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Nmap Scanner Engine: scanner/nmap_scanner.py

PURPOSE:
Interfaces with Nmap using the python-nmap library to execute controlled,
non-destructive network port scans and parse structured results.

SECURITY & CONSTRAINTS:
- Uses python-nmap PortScanner API safely (no shell=True or string concatenation).
- Fixed scan profile: -sV --top-ports 100 --version-light -T3
- Handles missing Nmap binary, unreachable hosts, timeouts, and exceptions gracefully.
=============================================================================
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
import logging
from typing import Dict, Any

try:
    import nmap
except ImportError:
    nmap = None

# Configure module logger
logger = logging.getLogger(__name__)

# Safe, conservative scan arguments (top 100 TCP ports, light service version detection)
DEFAULT_SCAN_ARGS = "-sV --top-ports 100 --version-light -T3"
DEFAULT_TIMEOUT_SECONDS = 60


class ScannerException(Exception):
    """Base exception class for SecureScan scanner errors."""
    pass


class ScannerUnavailableError(ScannerException):
    """Raised when Nmap executable is not installed or not found in system PATH."""
    pass


class ScanTimeoutError(ScannerException):
    """Raised when Nmap scan execution exceeds allowed timeout limit."""
    pass


class ScanExecutionError(ScannerException):
    """Raised when an error occurs during Nmap scan execution."""
    pass


def run_scan(target: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Dict[str, Any]:
    """
    Executes a controlled Nmap scan against a validated target host.

    Args:
        target (str): Validated single host IP or hostname.
        timeout (int): Maximum scan duration in seconds (default: 60).

    Returns:
        Dict[str, Any]: Structured scan result data model containing host status, duration,
                        and list of detected open ports with service details.

    Raises:
        ScannerUnavailableError: If Nmap binary is missing or cannot run.
        ScanTimeoutError: If scan execution times out.
        ScanExecutionError: If scan fails due to execution or network errors.
    """
    if nmap is None:
        logger.error("python-nmap module is not installed in Python environment.")
        raise ScannerUnavailableError("Nmap wrapper library (python-nmap) is not available.")

    # Initialize Nmap PortScanner
    try:
        nm = nmap.PortScanner()
    except (nmap.PortScannerError, FileNotFoundError, PermissionError) as e:
        logger.error(f"Nmap executable initialization failed: {e}")
        raise ScannerUnavailableError(
            "Nmap is not installed or cannot be found. Install Nmap for Windows and ensure it is available in your system PATH."
        )
    except Exception as e:
        logger.error(f"Unexpected error initializing PortScanner: {e}")
        raise ScannerUnavailableError("Unable to initialize scanner engine.")

    scan_start_time = datetime.now()

    def _execute_nmap() -> Dict[str, Any]:
        return nm.scan(hosts=target, arguments=DEFAULT_SCAN_ARGS, timeout=timeout)

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_execute_nmap)
            # Allow a slight grace period over Nmap timeout for thread completion
            future.result(timeout=timeout + 5)
    except FuturesTimeoutError:
        logger.warning(f"Scan timed out for target '{target}' after {timeout} seconds.")
        raise ScanTimeoutError(
            f"The scan operation for '{target}' timed out after {timeout} seconds."
        )
    except nmap.PortScannerError as e:
        logger.error(f"PortScannerError executing scan against {target}: {e}")
        raise ScanExecutionError(f"Nmap scan failed to execute: {e}")
    except Exception as e:
        logger.error(f"Unexpected scan execution error for target {target}: {e}")
        raise ScanExecutionError("The target did not respond or an unexpected error occurred during execution.")

    scan_end_time = datetime.now()
    duration_seconds = round((scan_end_time - scan_start_time).total_seconds(), 2)

    # Parse and structure scan results
    return _parse_scan_data(target, nm, duration_seconds, scan_start_time)


def _parse_scan_data(
    target: str, nm: Any, duration_seconds: float, start_time: datetime
) -> Dict[str, Any]:
    """
    Parses raw Nmap scan output into a clean, predictable dictionary structure.
    """
    result: Dict[str, Any] = {
        "target": target,
        "resolved_addresses": [],
        "host_status": "down",
        "hostname": target,
        "scan_started_at": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_duration_seconds": duration_seconds,
        "open_ports": [],
        "open_port_count": 0,
    }

    all_hosts = nm.all_hosts()
    if not all_hosts:
        logger.info(f"Target '{target}' returned no host data (host unreachable or filtered).")
        return result

    host_ip = all_hosts[0]
    result["resolved_addresses"] = [host_ip]

    host_info = nm[host_ip]
    status_info = host_info.get("status", {})
    result["host_status"] = status_info.get("state", "down")

    # Extract canonical hostname if resolved
    hostnames = host_info.get("hostnames", [])
    for hn in hostnames:
        if isinstance(hn, dict) and hn.get("name"):
            result["hostname"] = hn["name"]
            break

    # Parse open ports
    open_ports = []
    for proto in host_info.all_protocols():
        ports_dict = host_info[proto]
        for port_num, port_data in sorted(ports_dict.items()):
            if port_data.get("state") == "open":
                open_ports.append(
                    {
                        "port": int(port_num),
                        "protocol": str(proto).upper(),
                        "state": "open",
                        "service": port_data.get("name", "unknown") or "unknown",
                        "product": port_data.get("product", "") or "N/A",
                        "version": port_data.get("version", "") or "N/A",
                    }
                )

    result["open_ports"] = open_ports
    result["open_port_count"] = len(open_ports)
    return result
