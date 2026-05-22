import pytest
import re


# Adversarial payloads representing various attack scenarios related to
# SSH PublicKeyCallback authorization bypass and dependency version manipulation
ADVERSARIAL_PAYLOADS = [
    # Attempt to use vulnerable versions of golang.org/x/crypto
    "golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975",
    "golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2",
    "golang.org/x/crypto v0.0.0-20180904163835-0709b304e793",
    "golang.org/x/crypto v0.0.0-20170930174604-9419663f5a44",
    # Attempt to inject malicious replace directives
    "replace golang.org/x/crypto => evil.com/crypto v1.0.0",
    "replace golang.org/x/crypto => ../../../malicious v0.0.1",
    # Attempt to use pre-fix versions with known SSH vulnerabilities
    "golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83",
    "golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9",
    # Null/empty version strings
    "",
    "golang.org/x/crypto",
    # Malformed version strings
    "golang.org/x/crypto v0.0.0",
    "golang.org/x/crypto LATEST",
    # Path traversal in module paths
    "golang.org/x/crypto/../../../etc/passwd v1.0.0",
    # Version with special characters
    "golang.org/x/crypto v0.0.0-$(malicious)",
    "golang.org/x/crypto v0.0.0-`id`",
]

# The minimum safe version that fixes the PublicKeyCallback authorization bypass
# CVE related to misuse of ServerConfig.PublicKeyCallback
SAFE_VERSION_DATE = "20220315"  # Versions after this date are considered safe
KNOWN_SAFE_VERSION = "0.0.0-20220315"


def parse_crypto_version(version_string: str):
    """
    Parse a golang.org/x/crypto version string and return version components.
    Returns None if the version string is invalid or cannot be parsed safely.
    """
    if not version_string or not isinstance(version_string, str):
        return None

    # Sanitize: reject strings with shell injection characters
    dangerous_chars = ['$', '`', ';', '|', '&', '>', '<', '(', ')', '{', '}']
    for char in dangerous_chars:
        if char in version_string:
            return None

    # Reject path traversal attempts
    if '..' in version_string:
        return None

    # Must start with the expected module path
    if not version_string.startswith("golang.org/x/crypto"):
        return None

    # Extract version part
    parts = version_string.strip().split()
    if len(parts) < 2:
        return None

    version = parts[1]

    # Must match semver or pseudo-version format
    semver_pattern = r'^v\d+\.\d+\.\d+(-\d{14}-[a-f0-9]+)?$'
    if not re.match(semver_pattern, version):
        return None

    return version


def is_version_safe_from_pubkey_bypass(version: str) -> bool:
    """
    Check if a golang.org/x/crypto version is safe from the
    PublicKeyCallback authorization bypass vulnerability.

    The vulnerability exists in versions before the fix was applied.
    Safe versions are those >= v0.0.0-20220315... or tagged releases >= v0.1.0
    """
    if version is None:
        return False

    # Tagged releases v0.1.0 and above are safe
    tagged_pattern = r'^v(\d+)\.(\d+)\.(\d+)$'
    tagged_match = re.match(tagged_pattern, version)
    if tagged_match:
        major, minor, patch = int(tagged_match.group(1)), int(tagged_match.group(2)), int(tagged_match.group(3))
        # v0.1.0 and above are safe
        if major > 0 or (major == 0 and minor >= 1):
            return True
        # v0.0.0 without date is not safe
        return False

    # Pseudo-version format: v0.0.0-YYYYMMDDHHMMSS-hash
    pseudo_pattern = r'^v0\.0\.0-(\d{8})\d{6}-[a-f0-9]+$'
    pseudo_match = re.match(pseudo_pattern, version)
    if pseudo_match:
        date_str = pseudo_match.group(1)
        # Must be after the fix date
        return date_str >= SAFE_VERSION_DATE

    return False


def validate_go_mod_dependency(dep_line: str) -> dict:
    """
    Validate a go.mod dependency line for security properties.
    Returns a dict with 'valid', 'safe', and 'reason' keys.
    """
    result = {
        'valid': False,
        'safe': False,
        'reason': 'Unknown'
    }

    # Check for injection attempts
    dangerous_chars = ['$', '`', ';', '|', '&', '>', '<']
    for char in dangerous_chars:
        if char in dep_line:
            result['reason'] = f'Dangerous character detected: {char}'
            return result

    # Check for path traversal
    if '..' in dep_line:
        result['reason'] = 'Path traversal attempt detected'
        return result

    # Check for replace directive pointing to external/malicious source
    if dep_line.strip().startswith('replace'):
        result['reason'] = 'Replace directive requires manual review'
        result['valid'] = True
        result['safe'] = False
        return result

    version = parse_crypto_version(dep_line)
    if version is None:
        result['reason'] = 'Invalid or unparseable version string'
        return result

    result['valid'] = True
    result['safe'] = is_version_safe_from_pubkey_bypass(version)
    result['reason'] = f'Version {version} is {"safe" if result["safe"] else "potentially vulnerable"}'

    return result


@pytest.mark.parametrize("payload", ADVERSARIAL_PAYLOADS)
def test_ssh_pubkey_callback_version_security_invariant(payload):
    """
    Invariant: The security boundary for golang.org/x/crypto SSH PublicKeyCallback
    authorization bypass must be maintained. Any version of golang.org/x/crypto
    used must be validated as safe, and adversarial/malicious version strings
    must never be accepted as valid safe dependencies.

    Specifically:
    1. Injection payloads must never be parsed as valid versions
    2. Path traversal attempts must be rejected
    3. Known vulnerable version dates must not be marked as safe
    4. Replace directives to external sources must not be auto-approved
    """
    result = validate_go_mod_dependency(payload)

    # INVARIANT 1: Payloads with injection characters must never be valid
    dangerous_chars = ['$', '`', ';', '|', '&', '>', '<']
    has_injection = any(char in payload for char in dangerous_chars)
    if has_injection:
        assert not result['valid'], (
            f"SECURITY VIOLATION: Injection payload was accepted as valid: {payload!r}"
        )
        assert not result['safe'], (
            f"SECURITY VIOLATION: Injection payload was marked as safe: {payload!r}"
        )

    # INVARIANT 2: Path traversal attempts must never be valid
    if '..' in payload:
        assert not result['valid'], (
            f"SECURITY VIOLATION: Path traversal payload was accepted as valid: {payload!r}"
        )
        assert not result['safe'], (
            f"SECURITY VIOLATION: Path traversal payload was marked as safe: {payload!r}"
        )

    # INVARIANT 3: Replace directives to external/relative paths must not be auto-approved as safe
    if payload.strip().startswith('replace'):
        assert not result['safe'], (
            f"SECURITY VIOLATION: Replace directive was auto-approved as safe: {payload!r}"
        )

    # INVARIANT 4: Known vulnerable version dates must not be marked safe
    vulnerable_dates = [
        "20200220", "20190308", "20180904", "20170930",
        "20210220", "20200622"
    ]
    for vuln_date in vulnerable_dates:
        if vuln_date in payload:
            assert not result['safe'], (
                f"SECURITY VIOLATION: Known vulnerable version date {vuln_date} "
                f"was marked as safe in payload: {payload!r}"
            )

    # INVARIANT 5: Empty or malformed strings must not be marked as safe
    if not payload or payload == "golang.org/x/crypto" or payload == "golang.org/x/crypto v0.0.0":
        assert not result['safe'], (
            f"SECURITY VIOLATION: Empty/malformed version was marked as safe: {payload!r}"
        )


@pytest.mark.parametrize("safe_version,expected_safe", [
    ("golang.org/x/crypto v0.1.0", True),
    ("golang.org/x/crypto v0.2.0", True),
    ("golang.org/x/crypto v1.0.0", True),
    ("golang.org/x/crypto v0.0.0-20220315164138-7b1a5545e2a4", True),
    ("golang.org/x/crypto v0.0.0-20230101000000-abcdef123456", True),
    ("golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975", False),
    ("golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2", False),
    ("golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83", False),
])
def test_safe_version_detection_invariant(safe_version, expected_safe):
    """
    Invariant: Version safety detection must correctly classify golang.org/x/crypto
    versions as safe or vulnerable with respect to the PublicKeyCallback
    authorization bypass vulnerability. Safe versions must be correctly identified
    and vulnerable versions must never be falsely marked as safe.
    """
    result = validate_go_mod_dependency(safe_version)

    assert result['valid'], (
        f"Valid version string was rejected: {safe_version!r}, reason: {result['reason']}"
    )

    assert result['safe'] == expected_safe, (
        f"Version safety mismatch for {safe_version!r}: "
        f"expected safe={expected_safe}, got safe={result['safe']}, "
        f"reason: {result['reason']}"
    )

    # Critical: vulnerable versions must NEVER be falsely marked as safe
    if not expected_safe:
        assert not result['safe'], (
            f"CRITICAL SECURITY VIOLATION: Vulnerable version was marked as safe: {safe_version!r}"
        )