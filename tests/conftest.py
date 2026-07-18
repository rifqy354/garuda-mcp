"""Pytest configuration for BugBounty MCP tests."""

import pytest
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    from bugbounty_mcp.models import Vulnerability, Severity, VulnerabilityType

    return Vulnerability(
        name="Test XSS",
        type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        target="https://example.com",
        url="https://example.com/search?q=test",
        description="Reflected XSS in search parameter",
        impact="Allows execution of arbitrary JavaScript",
        remediation="Escape user input properly",
        poc='<script>alert(1)</script>',
    )


@pytest.fixture
def sample_report():
    """Create a sample report for testing."""
    from bugbounty_mcp.models import Report, Vulnerability, Severity, VulnerabilityType

    return Report(
        title="Security Assessment Report",
        target="https://example.com",
        scope=["https://example.com", "https://api.example.com"],
        vulnerabilities=[
            Vulnerability(
                name="XSS",
                severity=Severity.HIGH,
                type=VulnerabilityType.XSS,
                target="https://example.com",
            ),
            Vulnerability(
                name="SQL Injection",
                severity=Severity.CRITICAL,
                type=VulnerabilityType.SQLI,
                target="https://api.example.com",
            ),
        ],
    )
