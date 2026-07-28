"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Target Input Validator: scanner/validator.py

PURPOSE:
Provides robust target normalization and validation functions to ensure that
submitted scan targets are strictly valid single hosts (IPv4, IPv6, localhost,
or DNS hostnames) and free of malicious shell characters or unsupported syntax.

SECURITY:
- Rejects shell execution characters (;, &, |, `, $, quotes, newlines).
- Rejects URL protocols (http://, https://).
- Rejects URL paths, query strings, and fragments.
- Rejects CIDR notation (/24) and port specifications.
- Rejects multiple targets (commas/spaces).
- Enforces strict hostname label rules using Python standard libraries.
=============================================================================
"""

import ipaddress
import re
from typing import Tuple

# Maximum total length for target inputs (standard max DNS hostname length)
MAX_TARGET_LENGTH = 253

# Regex matching dangerous characters that could indicate command injection attempts or bad formatting
DANGEROUS_CHARS_PATTERN = re.compile(r'[\s;&|`$"\'<>\\?\r\n\t,]')


def validate_target(target: str) -> Tuple[bool, str, str]:
    """
    Validates and normalizes a user-submitted target input string.

    Args:
        target (str): Raw target string entered by the user.

    Returns:
        Tuple[bool, str, str]: (is_valid, normalized_target, error_message)
            - is_valid (bool): True if target passes all validation rules, False otherwise.
            - normalized_target (str): Lowercased/canonical target string if valid, empty string otherwise.
            - error_message (str): Human-readable error message if invalid, empty string if valid.
    """
    if not isinstance(target, str):
        return False, "", "Target must be a text string."

    # 1. Strip leading and trailing whitespace
    cleaned_target = target.strip()

    # 2. Reject empty input
    if not cleaned_target:
        return False, "", "Target input cannot be empty."

    # 3. Enforce maximum length
    if len(cleaned_target) > MAX_TARGET_LENGTH:
        return (
            False,
            "",
            f"Target input exceeds maximum allowed length of {MAX_TARGET_LENGTH} characters.",
        )

    # 4. Reject protocols such as http://, https://, ftp://, or leading ://
    if "://" in cleaned_target or cleaned_target.lower().startswith(
        ("http:", "https:", "ftp:")
    ):
        return (
            False,
            "",
            "URL protocols (e.g. http://, https://) are not allowed. Enter only an IP address or hostname.",
        )

    # 5. Detect and reject dangerous characters, spaces, and commas
    if DANGEROUS_CHARS_PATTERN.search(cleaned_target):
        return False, "", "Target contains invalid characters, spaces, or multiple inputs."

    # 6. Reject CIDR notation and paths (slashes)
    if "/" in cleaned_target:
        return (
            False,
            "",
            "CIDR notation (/24) and URL paths are not supported. Scan only single hosts.",
        )

    # 7. Reject query strings and fragments
    if "?" in cleaned_target or "#" in cleaned_target:
        return False, "", "Query parameters and URL fragments are not allowed."

    # 8. Reject targets starting with a hyphen (command-line flag prevention)
    if cleaned_target.startswith("-"):
        return False, "", "Target cannot start with a hyphen or command flag."

    # 9. Test IPv4 validation using Python standard library ipaddress module
    try:
        ipv4_obj = ipaddress.IPv4Address(cleaned_target)
        return True, str(ipv4_obj), ""
    except ValueError:
        pass

    # 10. Test IPv6 validation using Python standard library ipaddress module
    try:
        ipv6_obj = ipaddress.IPv6Address(cleaned_target)
        return True, str(ipv6_obj), ""
    except ValueError:
        pass

    # If it contains colons but failed IPv6 parsing, it is an invalid format or embedded port (e.g., host:80)
    if ":" in cleaned_target:
        return False, "", "Port numbers embedded in target (e.g., host:80) are not allowed."

    # 11. Normalize hostnames to lowercase
    normalized_hostname = cleaned_target.lower()

    # 12. Accept localhost explicitly
    if normalized_hostname == "localhost":
        return True, "localhost", ""

    # 13. Validate DNS Hostname syntax
    if (
        ".." in normalized_hostname
        or normalized_hostname.startswith(".")
        or normalized_hostname.endswith(".")
    ):
        return False, "", "Target contains invalid domain formatting."

    labels = normalized_hostname.split(".")

    for label in labels:
        if not label:
            return False, "", "Domain contains empty labels."
        if len(label) > 63:
            return False, "", "Domain label exceeds maximum length of 63 characters."
        if label.startswith("-") or label.endswith("-"):
            return False, "", "Domain labels cannot start or end with a hyphen."
        # Label must contain only alphanumeric characters and hyphens
        if not re.match(r"^[a-z0-9-]+$", label):
            return False, "", "Domain label contains invalid characters."

    return True, normalized_hostname, ""
