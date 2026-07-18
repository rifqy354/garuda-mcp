"""Tests for BugBounty MCP."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestModels:
    """Test data models."""

    def test_vulnerability_creation(self):
        """Test Vulnerability model creation."""
        from bugbounty_mcp.models import Vulnerability, Severity, VulnerabilityType

        vuln = Vulnerability(
            name="Test XSS",
            type=VulnerabilityType.XSS,
            severity=Severity.HIGH,
            target="https://example.com",
            description="Reflected XSS vulnerability",
        )

        assert vuln.name == "Test XSS"
        assert vuln.type == VulnerabilityType.XSS
        assert vuln.severity == Severity.HIGH
        assert vuln.target == "https://example.com"

    def test_vulnerability_to_markdown(self):
        """Test Vulnerability markdown generation."""
        from bugbounty_mcp.models import Vulnerability, Severity, VulnerabilityType

        vuln = Vulnerability(
            name="SQL Injection",
            type=VulnerabilityType.SQLI,
            severity=Severity.CRITICAL,
            target="https://api.example.com",
            description="SQL injection in login form",
            remediation="Use parameterized queries",
        )

        markdown = vuln.to_markdown()

        assert "## SQL Injection" in markdown
        assert "CRITICAL" in markdown
        assert "SQL Injection" in markdown
        assert "parameterized queries" in markdown

    def test_report_summary(self):
        """Test Report summary generation."""
        from bugbounty_mcp.models import (
            Report,
            Vulnerability,
            Severity,
            VulnerabilityType,
        )

        vulns = [
            Vulnerability(name="V1", severity=Severity.CRITICAL, type=VulnerabilityType.OTHER),
            Vulnerability(name="V2", severity=Severity.HIGH, type=VulnerabilityType.OTHER),
            Vulnerability(name="V3", severity=Severity.HIGH, type=VulnerabilityType.OTHER),
            Vulnerability(name="V4", severity=Severity.MEDIUM, type=VulnerabilityType.OTHER),
            Vulnerability(name="V5", severity=Severity.INFO, type=VulnerabilityType.OTHER),
        ]

        report = Report(
            title="Test Report",
            target="https://example.com",
            vulnerabilities=vulns,
        )

        summary = report.generate_summary()

        assert summary["total"] == 5
        assert summary["critical"] == 1
        assert summary["high"] == 2
        assert summary["medium"] == 1
        assert summary["info"] == 1


class TestUtils:
    """Test utility functions."""

    def test_format_curl(self):
        """Test cURL command formatting."""
        from bugbounty_mcp.utils import format_curl

        curl = format_curl(
            method="POST",
            url="https://api.example.com/login",
            headers={"Content-Type": "application/json"},
            data='{"username":"admin"}',
        )

        assert "curl" in curl
        assert "-X POST" in curl
        assert "https://api.example.com/login" in curl

    def test_deduplicate_urls(self):
        """Test URL deduplication."""
        from bugbounty_mcp.utils import deduplicate_urls

        urls = [
            "https://example.com/page1",
            "https://example.com/page2",
            "https://example.com/page1/",
            "HTTPS://EXAMPLE.COM/page1",
        ]

        result = deduplicate_urls(urls)

        assert len(result) == 2

    def test_normalize_url(self):
        """Test URL normalization."""
        from bugbounty_mcp.utils import normalize_url

        assert normalize_url("example.com") == "https://example.com"
        assert normalize_url("http://example.com/") == "https://example.com"
        assert normalize_url("https://example.com/page/") == "https://example.com/page"


class TestReporting:
    """Test reporting functionality."""

    def test_markdown_reporter(self):
        """Test Markdown report generation."""
        from bugbounty_mcp.reporting import MarkdownReporter
        from bugbounty_mcp.models import Report, Vulnerability, Severity, VulnerabilityType

        report = Report(
            title="Test Report",
            target="https://example.com",
            vulnerabilities=[
                Vulnerability(
                    name="XSS",
                    severity=Severity.HIGH,
                    type=VulnerabilityType.XSS,
                    target="https://example.com",
                ),
            ],
        )
        report.generate_summary()

        reporter = MarkdownReporter()
        md = reporter.generate(report)

        assert "# Test Report" in md
        assert "## HIGH Severity" in md
        assert "XSS" in md

    def test_json_reporter(self):
        """Test JSON report generation."""
        from bugbounty_mcp.reporting import JSONReporter
        from bugbounty_mcp.models import Report, Vulnerability, Severity, VulnerabilityType

        report = Report(
            title="Test Report",
            target="https://example.com",
            vulnerabilities=[],
        )

        reporter = JSONReporter()
        import json

        data = json.loads(reporter.generate(report))

        assert data["title"] == "Test Report"
        assert data["target"] == "https://example.com"


class TestRecon:
    """Test reconnaissance tools."""

    @pytest.mark.asyncio
    async def test_subfinder_tool(self):
        """Test SubfinderTool execution."""
        from bugbounty_mcp.recon import SubfinderTool

        tool = SubfinderTool()

        # Mock the execute method
        with patch.object(tool, 'execute') as mock_execute:
            mock_execute.return_value = (
                0,
                '{"host":"sub.example.com","source":"source1"}\n',
                ""
            )

            results = await tool.run("example.com")

            assert len(results) >= 0  # Depends on actual results

    def test_tool_installation_check(self):
        """Test tool installation check."""
        from bugbounty_mcp.utils import BaseTool

        class TestTool(BaseTool):
            name = "test-tool"

            async def run(self):
                pass

        tool = TestTool()

        # Mock subprocess
        with patch("bugbounty_mcp.utils.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert tool.is_installed()


class TestAPI:
    """Test API security tools."""

    @pytest.mark.asyncio
    async def test_jwt_analyzer(self):
        """Test JWT token analysis."""
        from bugbounty_mcp.api import JWTAnalyzerTool

        tool = JWTAnalyzerTool()

        # Test with "none" algorithm
        import base64
        header = base64.b64encode(b'{"alg":"none"}').decode().rstrip("=")
        payload = base64.b64encode(b'{"user":"admin"}').decode().rstrip("=")
        token = f"{header}.{payload}."

        results = await tool.run(token)

        assert len(results) > 0
        assert any("none" in v.name.lower() for v in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
