"""AI workflow orchestrator for BugBounty MCP."""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Type

from ..models import Endpoint, Report, ScanResult, ScanStatus, Severity, Subdomain, Vulnerability
from ..recon import SubfinderTool, HttpxTool, NaabuTool, KatanaTool, GauTool
from ..web import FfufTool, NucleiTool, DalfoxTool, ArjunTool
from ..api import GraphQLScannerTool, OpenAPIAnalyzerTool, JWTAnalyzerTool
from ..utils import AsyncToolRunner


class AIOrchestrator:
    """
    AI-powered workflow orchestrator for automated security testing.

    This module intelligently selects and chains security tools
    based on target characteristics and findings.
    """

    def __init__(self, max_concurrent: int = 5):
        self.runner = AsyncToolRunner(max_concurrent)
        self.results: List[ScanResult] = []

    async def recon_target(
        self,
        target: str,
        intensity: str = "normal"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive reconnaissance on a target.

        Args:
            target: Target domain or URL
            intensity: "quick", "normal", or "deep"

        Returns:
            Dictionary with subdomains, endpoints, and scan results
        """
        results = {
            "target": target,
            "subdomains": [],
            "endpoints": [],
            "scan_results": [],
            "started_at": datetime.utcnow().isoformat(),
        }

        # Step 1: Subdomain enumeration
        subfinder = SubfinderTool()
        subdomains = await subfinder.run(target, all_sources=(intensity == "deep"))
        results["subdomains"] = [s.model_dump() for s in subdomains]

        # Step 2: HTTP probing
        if subdomains:
            targets = [f"https://{s.domain}" for s in subdomains]
            targets.append(f"https://{target}")

            httpx = HttpxTool()
            endpoints = await httpx.run(
                targets=targets,
                threads=50 if intensity == "deep" else 30,
            )
            results["endpoints"] = [e.model_dump() for e in endpoints]

        # Step 3: Deep crawling for high intensity
        if intensity == "deep":
            katana = KatanaTool()
            for endpoint in results["endpoints"][:10]:  # Limit crawling
                try:
                    crawled = await katana.run(
                        url=endpoint.get("url", ""),
                        depth=5,
                        max_pages=200,
                    )
                    results["endpoints"].extend(
                        [e.model_dump() for e in crawled]
                    )
                except Exception:
                    pass

        results["completed_at"] = datetime.utcnow().isoformat()
        return results

    async def scan_web_vulnerabilities(
        self,
        target: str,
        scan_types: Optional[List[str]] = None,
        nuclei_tags: Optional[List[str]] = None,
    ) -> Dict[str, List[Vulnerability]]:
        """
        Scan for web vulnerabilities.

        Args:
            target: Target URL
            scan_types: Types of scans to perform
            nuclei_tags: Nuclei template tags

        Returns:
            Dictionary mapping scan type to vulnerabilities found
        """
        if scan_types is None:
            scan_types = ["nuclei", "xss", "params"]

        if nuclei_tags is None:
            nuclei_tags = ["cves", "vulnerabilities", "exposure"]

        results: Dict[str, List[Vulnerability]] = {}

        # Nuclei vulnerability scan
        if "nuclei" in scan_types:
            nuclei = NucleiTool()
            vulns = await nuclei.run(
                target=target,
                tags=nuclei_tags,
                severity=["critical", "high", "medium"],
            )
            results["nuclei"] = vulns

        # XSS scanning
        if "xss" in scan_types:
            dalfox = DalfoxTool()
            vulns = await dalfox.run(url=target, mining=True)
            results["xss"] = vulns

        # Parameter discovery
        if "params" in scan_types:
            arjun = ArjunTool()
            params = await arjun.run(url=target)
            results["params"] = []
            if params:
                results["params"].append(Vulnerability(
                    name="Discovered Parameters",
                    type=VulnerabilityType.OTHER,
                    severity=Severity.INFO,
                    target=target,
                    description=f"Discovered {len(params)} parameters: {', '.join(params[:20])}",
                ))

        return results

    async def analyze_api(
        self,
        target: str,
        api_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        Analyze an API for security issues.

        Args:
            target: API endpoint URL
            api_type: "rest", "graphql", or "auto"

        Returns:
            Dictionary with API analysis results
        """
        results: Dict[str, Any] = {
            "target": target,
            "vulnerabilities": [],
            "endpoints": [],
        }

        # Try GraphQL if suspected
        if api_type in ["graphql", "auto"]:
            graphql = GraphQLScannerTool()
            vulns = await graphql.run(target)
            results["vulnerabilities"].extend(vulns)

            # If introspection works, it's likely GraphQL
            if any("graphql" in str(v.name).lower() for v in vulns):
                results["api_type"] = "graphql"
                return results

        # Try OpenAPI discovery
        if api_type in ["rest", "auto"]:
            # Common OpenAPI paths
            openapi_paths = [
                f"{target.rstrip('/')}/swagger.json",
                f"{target.rstrip('/')}/api-docs",
                f"{target.rstrip('/')}/openapi.json",
            ]

            openapi = OpenAPIAnalyzerTool()
            for path in openapi_paths:
                vulns = await openapi.run(path)
                if vulns:
                    results["vulnerabilities"].extend(vulns)
                    results["api_type"] = "rest"
                    results["spec_url"] = path
                    break

        return results

    async def full_assessment(
        self,
        target: str,
        scope: Optional[List[str]] = None,
    ) -> Report:
        """
        Perform a full security assessment.

        Args:
            target: Primary target
            scope: Additional in-scope targets

        Returns:
            Assessment report
        """
        all_vulnerabilities: List[Vulnerability] = []
        all_endpoints: List[Endpoint] = []
        all_subdomains: List[Subdomain] = []

        # Recon phase
        recon_results = await self.recon_target(target)
        all_subdomains.extend([
            Subdomain(**s) for s in recon_results.get("subdomains", [])
        ])
        all_endpoints.extend([
            Endpoint(**e) for e in recon_results.get("endpoints", [])
        ])

        # Scan phase
        for endpoint in all_endpoints[:20]:  # Limit scans
            url = endpoint.url if isinstance(endpoint, Endpoint) else endpoint.get("url", "")
            if not url:
                continue

            try:
                scan_results = await self.scan_web_vulnerabilities(url)
                for vulns in scan_results.values():
                    all_vulnerabilities.extend(vulns)
            except Exception:
                pass

            # API analysis
            try:
                api_results = await self.analyze_api(url)
                all_vulnerabilities.extend(api_results.get("vulnerabilities", []))
            except Exception:
                pass

        # Generate report
        report = Report(
            title=f"Security Assessment Report - {target}",
            target=target,
            scope=scope or [target],
            vulnerabilities=all_vulnerabilities,
        )
        report.generate_summary()

        return report

    async def suggest_tools(
        self,
        target: str,
        objective: str
    ) -> List[Dict[str, str]]:
        """
        Suggest appropriate tools based on target and objective.

        Args:
            target: Target URL or domain
            objective: Testing objective

        Returns:
            List of suggested tools with descriptions
        """
        suggestions: List[Dict[str, str]] = []

        # Analyze target type
        if ".apk" in target or "android" in objective.lower():
            suggestions.extend([
                {"tool": "jadx", "purpose": "Decompile Android APK"},
                {"tool": "apkanalyzer", "purpose": "Static APK security analysis"},
            ])

        if ".exe" in target or ".elf" in target or "binary" in objective.lower():
            suggestions.extend([
                {"tool": "checksec", "purpose": "Check binary security features"},
                {"tool": "ropgadget", "purpose": "Find ROP gadgets"},
                {"tool": "ghidra", "purpose": "Full binary analysis"},
            ])

        if "api" in objective.lower() or "/graphql" in target:
            suggestions.extend([
                {"tool": "graphql_scanner", "purpose": "GraphQL security testing"},
                {"tool": "rest_fuzzer", "purpose": "REST API fuzzing"},
            ])

        if "web" in objective.lower() or "http" in target:
            suggestions.extend([
                {"tool": "nuclei", "purpose": "Vulnerability scanning"},
                {"tool": "ffuf", "purpose": "Directory/content discovery"},
                {"tool": "dalfox", "purpose": "XSS testing"},
                {"tool": "sqlmap", "purpose": "SQL injection testing"},
            ])

        if "subdomain" in objective.lower():
            suggestions.extend([
                {"tool": "subfinder", "purpose": "Passive subdomain enumeration"},
                {"tool": "httpx", "purpose": "Alive host detection"},
            ])

        return suggestions


# Import missing type
from ..models import VulnerabilityType
