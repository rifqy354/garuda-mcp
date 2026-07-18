"""CLI interface for BugBounty MCP."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer

from .config import init_settings
from .models import Vulnerability, VulnerabilityType, Severity, Report
from .reporting import Reporter
from .recon import SubfinderTool, HttpxTool, KatanaTool, NaabuTool
from .web import NucleiTool, FfufTool, DalfoxTool
from .ai import AIOrchestrator

app = typer.Typer(help="BugBounty MCP CLI")

reporter = Reporter()


@app.command()
def recon(
    target: str = typer.Argument(..., help="Target domain or URL"),
    intensity: str = typer.Option("normal", help="Recon intensity: quick, normal, deep"),
) -> None:
    """Perform reconnaissance on a target."""
    async def run():
        ai = AIOrchestrator()
        results = await ai.recon_target(target, intensity=intensity)

        typer.echo(f"\n=== Recon Results for {target} ===\n")
        typer.echo(f"Subdomains found: {len(results.get('subdomains', []))}")
        typer.echo(f"Endpoints found: {len(results.get('endpoints', []))}")

        if results.get("subdomains"):
            typer.echo("\nSubdomains:")
            for sub in results["subdomains"][:20]:
                typer.echo(f"  - {sub.get('domain')}")

        if results.get("endpoints"):
            typer.echo("\nEndpoints:")
            for ep in results["endpoints"][:20]:
                url = ep.get("url", "")
                status = ep.get("status_code", "?")
                typer.echo(f"  - {url} [{status}]")

    asyncio.run(run())


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    scan_type: str = typer.Option("all", help="Scan type: nuclei, xss, params, all"),
    tags: str = typer.Option("cves,vulnerabilities", help="Nuclei tags"),
) -> None:
    """Scan for web vulnerabilities."""
    async def run():
        ai = AIOrchestrator()

        scan_types = None
        nuclei_tags = tags.split(",") if tags else None

        if scan_type != "all":
            scan_types = [scan_type]

        results = await ai.scan_web_vulnerabilities(
            target,
            scan_types=scan_types,
            nuclei_tags=nuclei_tags,
        )

        typer.echo(f"\n=== Scan Results for {target} ===\n")

        total = sum(len(vulns) for vulns in results.values())
        typer.echo(f"Total vulnerabilities found: {total}\n")

        for scan_name, vulns in results.items():
            if vulns:
                typer.echo(f"\n--- {scan_name.upper()} ({len(vulns)}) ---")
                for vuln in vulns:
                    severity = vuln.severity.value.upper()
                    typer.echo(f"  [{severity}] {vuln.name}")
                    typer.echo(f"           Type: {vuln.type.value}")

    asyncio.run(run())


@app.command()
def subdomain_enum(
    domain: str = typer.Argument(..., help="Domain to enumerate"),
    all_sources: bool = typer.Option(False, help="Use all sources"),
) -> None:
    """Enumerate subdomains."""
    async def run():
        tool = SubfinderTool()
        results = await tool.run(domain, all_sources=all_sources)

        typer.echo(f"\nFound {len(results)} subdomains for {domain}:\n")

        for sub in results:
            cname = sub.cnames[0] if sub.cnames else ""
            cname_str = f" -> {cname}" if cname else ""
            typer.echo(f"  {sub.domain}{cname_str}")

    asyncio.run(run())


@app.command()
def vuln_scan(
    target: str = typer.Argument(..., help="Target URL"),
    tags: str = typer.Option("cves,vulnerabilities", help="Nuclei tags"),
    output: Optional[Path] = typer.Option(None, help="Output file"),
    format: str = typer.Option("markdown", help="Report format"),
) -> None:
    """Scan for vulnerabilities using Nuclei."""
    async def run():
        nuclei = NucleiTool()
        nuclei_tags = tags.split(",") if tags else None

        vulns = await nuclei.run(
            target=target,
            tags=nuclei_tags,
            severity=["critical", "high", "medium"],
        )

        typer.echo(f"\nFound {len(vulns)} vulnerabilities:\n")

        for vuln in vulns:
            severity = vuln.severity.value.upper()
            color = typer.colors.RED if vuln.severity == Severity.CRITICAL else \
                    typer.colors.ORANGE if vuln.severity == Severity.HIGH else \
                    typer.colors.YELLOW if vuln.severity == Severity.MEDIUM else \
                    typer.colors.GREEN
            typer.secho(f"  [{severity}] {vuln.name}", fg=color)
            typer.echo(f"           {vuln.url or vuln.target}")

        # Generate report if output specified
        if output:
            report = Report(
                title=f"Vulnerability Scan - {target}",
                target=target,
                vulnerabilities=vulns,
            )
            report.generate_summary()

            content = reporter.generate_report(report, format)
            output.write_text(content)
            typer.echo(f"\nReport saved to {output}")

    asyncio.run(run())


@app.command()
def checksec(
    binary: Path = typer.Argument(..., help="Binary file to check"),
) -> None:
    """Check binary security features."""
    async def run():
        from .binary import ChecksecTool

        tool = ChecksecTool()
        result = await tool.run(str(binary))

        typer.echo(f"\n=== Binary Analysis: {binary.name} ===\n")

        checks = [
            ("NX", "nx"),
            ("PIE", "pie"),
            ("Canary", "canary"),
            ("RELRO", "relro"),
            ("Stripped", "stripped"),
            ("Static", "static"),
        ]

        for name, attr in checks:
            value = getattr(result, attr, None)
            if value is None:
                continue

            color = typer.colors.RED if not value and name in ["NX", "PIE", "Canary"] \
                    else typer.colors.GREEN if value and name in ["NX", "PIE", "Canary"] \
                    else typer.colors.YELLOW

            status = "✓ Yes" if value else "✗ No"
            if isinstance(value, str) and value != "no":
                status = value

            typer.secho(f"  {name:12}: {status}", fg=color)

        if result.architecture:
            typer.echo(f"\n  Architecture: {result.architecture}")

        if result.size:
            typer.echo(f"  Size: {result.size:,} bytes")

    asyncio.run(run())


@app.command()
def report(
    title: str = typer.Argument(..., help="Report title"),
    target: str = typer.Argument(..., help="Target"),
    input_file: Path = typer.Option(..., "-i", help="Input JSON file with vulnerabilities"),
    output: Optional[Path] = typer.Option(None, "-o", help="Output file"),
    format: str = typer.Option("markdown", help="Output format"),
) -> None:
    """Generate a vulnerability report."""
    import json

    # Load vulnerabilities from file
    with open(input_file) as f:
        data = json.load(f)
        vulns_data = data if isinstance(data, list) else data.get("vulnerabilities", [])

    vulns = []
    for v in vulns_data:
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

    report_obj = Report(
        title=title,
        target=target,
        vulnerabilities=vulns,
    )
    report_obj.generate_summary()

    content = reporter.generate_report(report_obj, format)

    if output:
        output.write_text(content)
        typer.echo(f"Report saved to {output}")
    else:
        typer.echo(content)


if __name__ == "__main__":
    app()
