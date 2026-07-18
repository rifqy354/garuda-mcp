"""Main MCP server for BugBounty MCP."""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP

from .config import Settings, init_settings
from .models import (
    BinaryInfo,
    Endpoint,
    Function,
    Report,
    ScanStatus,
    StringEntry,
    Subdomain,
    Vulnerability,
)
from .reporting import Reporter
from .recon import (
    SubfinderTool,
    HttpxTool,
    NaabuTool,
    KatanaTool,
    GauTool,
    WaybackurlsTool,
    DnsxTool,
)
from .web import (
    FfufTool,
    NucleiTool,
    DalfoxTool,
    ArjunTool,
    ParamSpiderTool,
    SqlmapTool,
)
from .api import (
    GraphQLScannerTool,
    OpenAPIAnalyzerTool,
    JWTAnalyzerTool,
    RESTAPIFuzzerTool,
)
from .ghidra import GhidraTool
from .binary import (
    ChecksecTool,
    ROPGadgetTool,
    OneGadgetTool,
    StringsTool,
    ReadelfTool,
    ObjdumpTool,
)
from .mobile import (
    JadxTool,
    ApktoolTool,
    ApkAnalyzerTool,
    ClassDumpTool,
    FridaTool,
)
from .ai import AIOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class BugBountyMCP:
    """Main MCP server class for BugBounty tools."""

    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the MCP server."""
        self.settings = init_settings(config_path)
        self.reporter = Reporter()
        self.ai = AIOrchestrator()

        # Initialize FastMCP server
        self.mcp = FastMCP(
            name="BugBounty MCP",
            description="Security testing tools for bug bounty hunting",
        )

        # Register all tools
        self._register_recon_tools()
        self._register_web_tools()
        self._register_api_tools()
        self._register_burp_tools()
        self._register_ghidra_tools()
        self._register_binary_tools()
        self._register_mobile_tools()
        self._register_reporting_tools()
        self._register_ai_tools()

    def _register_recon_tools(self) -> None:
        """Register reconnaissance tools."""

        @self.mcp.tool()
        async def subdomain_enum(
            domain: str,
            all_sources: bool = False,
        ) -> List[Dict[str, Any]]:
            """Enumerate subdomains using passive sources."""
            tool = SubfinderTool()
            results = await tool.run(domain, all_sources=all_sources)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def port_scan(
            host: str,
            top_ports: int = 100,
        ) -> List[int]:
            """Scan common ports on a host."""
            tool = NaabuTool()
            return await tool.run(host, top_ports=top_ports)

        @self.mcp.tool()
        async def probe_urls(
            targets: List[str],
            ports: Optional[List[int]] = None,
        ) -> List[Dict[str, Any]]:
            """Probe URLs for alive hosts."""
            tool = HttpxTool()
            results = await tool.run(targets, ports=ports)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def crawl_urls(
            url: str,
            depth: int = 3,
            js_crawl: bool = True,
        ) -> List[Dict[str, Any]]:
            """Crawl URLs for endpoint discovery."""
            tool = KatanaTool()
            results = await tool.run(url, depth=depth, js_crawl=js_crawl)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def discover_urls(domain: str) -> List[str]:
            """Discover URLs from web archives."""
            tool = GauTool()
            return await tool.run(domain)

    def _register_web_tools(self) -> None:
        """Register web security tools."""

        @self.mcp.tool()
        async def web_fuzz(
            url: str,
            wordlist: str,
            extensions: Optional[List[str]] = None,
        ) -> List[Dict[str, Any]]:
            """Fuzz web directories and parameters."""
            tool = FfufTool()
            results = await tool.run(url, wordlist, extensions=extensions)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def vuln_scan(
            target: str,
            tags: Optional[List[str]] = None,
            severity: Optional[List[str]] = None,
        ) -> List[Dict[str, Any]]:
            """Scan for vulnerabilities using Nuclei templates."""
            tool = NucleiTool()
            results = await tool.run(target, tags=tags, severity=severity)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def xss_scan(url: str) -> List[Dict[str, Any]]:
            """Scan for XSS vulnerabilities."""
            tool = DalfoxTool()
            results = await tool.run(url, mining=True)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def discover_params(url: str) -> List[str]:
            """Discover HTTP parameters."""
            tool = ArjunTool()
            return await tool.run(url)

    def _register_api_tools(self) -> None:
        """Register API security tools."""

        @self.mcp.tool()
        async def graphql_scan(endpoint: str) -> List[Dict[str, Any]]:
            """Scan GraphQL endpoint for vulnerabilities."""
            tool = GraphQLScannerTool()
            results = await tool.run(endpoint)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def openapi_scan(spec_url: str) -> List[Dict[str, Any]]:
            """Analyze OpenAPI specification."""
            tool = OpenAPIAnalyzerTool()
            results = await tool.run(spec_url)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def jwt_analyze(token: str) -> List[Dict[str, Any]]:
            """Analyze JWT token for vulnerabilities."""
            tool = JWTAnalyzerTool()
            results = await tool.run(token)
            return [r.model_dump() for r in results]

    def _register_burp_tools(self) -> None:
        """Register Burp Suite tools."""

        @self.mcp.tool()
        async def burp_passive_scan(url: str) -> List[Dict[str, Any]]:
            """Run Burp passive scan on URL."""
            from .burp import BurpTool
            tool = BurpTool()
            results = await tool.run_passive_scan(url)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def burp_active_scan(url: str) -> List[Dict[str, Any]]:
            """Run Burp active scan on URL."""
            from .burp import BurpTool
            tool = BurpTool()
            results = await tool.run_active_scan(url)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def burp_sitemap(base_url: str) -> List[Dict[str, Any]]:
            """Get Burp sitemap for URL."""
            from .burp import BurpTool
            tool = BurpTool()
            results = await tool.get_sitemap(base_url)
            return [r.model_dump() for r in results]

    def _register_ghidra_tools(self) -> None:
        """Register Ghidra analysis tools."""

        @self.mcp.tool()
        async def ghidra_analyze(binary_path: str) -> Dict[str, Any]:
            """Analyze binary using Ghidra."""
            tool = GhidraTool()
            return await tool.analyze(binary_path)

        @self.mcp.tool()
        async def ghidra_decompile(
            binary_path: str,
            function_name: str,
        ) -> str:
            """Decompile a specific function."""
            tool = GhidraTool()
            return await tool.decompile_function(binary_path, function_name)

        @self.mcp.tool()
        async def ghidra_functions(binary_path: str) -> List[Dict[str, Any]]:
            """List all functions in binary."""
            tool = GhidraTool()
            results = await tool.list_functions(binary_path)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def ghidra_strings(binary_path: str) -> List[Dict[str, Any]]:
            """Extract strings from binary."""
            tool = GhidraTool()
            results = await tool.get_strings(binary_path)
            return [r.model_dump() for r in results]

    def _register_binary_tools(self) -> None:
        """Register binary analysis tools."""

        @self.mcp.tool()
        async def checksec(binary_path: str) -> Dict[str, Any]:
            """Check security features of binary."""
            tool = ChecksecTool()
            result = await tool.run(binary_path)
            return result.model_dump()

        @self.mcp.tool()
        async def find_rop_gadgets(binary_path: str) -> List[Dict[str, str]]:
            """Find ROP gadgets in binary."""
            tool = ROPGadgetTool()
            return await tool.run(binary_path)

        @self.mcp.tool()
        async def find_one_gadgets(libc_path: str) -> List[Dict[str, Any]]:
            """Find one-gadget RCE in libc."""
            tool = OneGadgetTool()
            return await tool.run(libc_path)

        @self.mcp.tool()
        async def extract_strings(
            binary_path: str,
            min_length: int = 4,
        ) -> List[Dict[str, Any]]:
            """Extract strings from binary."""
            tool = StringsTool()
            results = await tool.run(binary_path, min_length=min_length)
            return [r.model_dump() for r in results]

    def _register_mobile_tools(self) -> None:
        """Register mobile security tools."""

        @self.mcp.tool()
        async def decompile_apk(apk_path: str) -> str:
            """Decompile Android APK using JADX."""
            tool = JadxTool()
            return await tool.run(apk_path)

        @self.mcp.tool()
        async def analyze_apk(apk_path: str) -> List[Dict[str, Any]]:
            """Analyze Android APK for security issues."""
            tool = ApkAnalyzerTool()
            results = await tool.run(apk_path)
            return [r.model_dump() for r in results]

        @self.mcp.tool()
        async def dump_ios_classes(binary_path: str) -> List[str]:
            """Dump Objective-C classes from iOS binary."""
            tool = ClassDumpTool()
            return await tool.run(binary_path)

    def _register_reporting_tools(self) -> None:
        """Register reporting tools."""

        @self.mcp.tool()
        async def generate_report(
            title: str,
            target: str,
            vulnerabilities: List[Dict[str, Any]],
            scope: Optional[List[str]] = None,
            format: str = "markdown",
        ) -> str:
            """Generate a vulnerability report."""
            from .models import Vulnerability, VulnerabilityType, Severity

            vulns = []
            for v in vulnerabilities:
                vulns.append(Vulnerability(
                    name=v.get("name", "Unknown"),
                    type=VulnerabilityType(v.get("type", "other")),
                    severity=Severity(v.get("severity", "info")),
                    target=v.get("target", target),
                    url=v.get("url"),
                    description=v.get("description", ""),
                    impact=v.get("impact"),
                    remediation=v.get("remediation"),
                    cvss=v.get("cvss"),
                    poc=v.get("poc"),
                ))

            report = Report(
                title=title,
                target=target,
                scope=scope or [target],
                vulnerabilities=vulns,
            )
            report.generate_summary()

            return self.reporter.generate_report(report, format)

        @self.mcp.tool()
        async def suggest_tools(
            target: str,
            objective: str,
        ) -> List[Dict[str, str]]:
            """Suggest appropriate tools based on target."""
            return await self.ai.suggest_tools(target, objective)

    def _register_ai_tools(self) -> None:
        """Register AI orchestrator tools."""

        @self.mcp.tool()
        async def full_recon(target: str) -> Dict[str, Any]:
            """Perform full reconnaissance on target."""
            return await self.ai.recon_target(target, intensity="normal")

        @self.mcp.tool()
        async def full_web_scan(target: str) -> Dict[str, List[Dict[str, Any]]]:
            """Perform full web vulnerability scan."""
            results = await self.ai.scan_web_vulnerabilities(target)
            return {
                k: [v.model_dump() for v in vulns]
                for k, vulns in results.items()
            }

        @self.mcp.tool()
        async def complete_assessment(
            target: str,
            scope: Optional[List[str]] = None,
        ) -> Dict[str, Any]:
            """Perform complete security assessment."""
            report = await self.ai.full_assessment(target, scope)
            return self.reporter.generate_report(report, "markdown")

    def run(self) -> None:
        """Run the MCP server."""
        logger.info("Starting BugBounty MCP Server...")
        self.mcp.run()


def main() -> None:
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="BugBounty MCP Server")
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    server = BugBountyMCP(config_path=args.config)
    server.run()


if __name__ == "__main__":
    main()
