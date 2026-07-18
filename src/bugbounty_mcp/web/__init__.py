"""Web security testing module for BugBounty MCP."""

import asyncio
from typing import Any, Dict, List, Optional

from ..models import Endpoint, Severity, Vulnerability, VulnerabilityType
from ..utils import BaseTool, format_curl


class FfufTool(BaseTool):
    """Fast web fuzzer."""

    name = "ffuf"
    description = "Fast web fuzzer for directory and parameter fuzzing"

    async def run(
        self,
        url: str,
        wordlist: str,
        mode: str = "directory",
        extensions: Optional[List[str]] = None,
        threads: int = 40,
        match_codes: Optional[List[int]] = None,
        filter_codes: Optional[List[int]] = None,
        timeout: int = 10,
        recursive: bool = False,
        recursion_depth: int = 2,
    ) -> List[Endpoint]:
        """Fuzz a URL using ffuf."""
        args = [
            "ffuf",
            "-u", f"{url.rstrip('/')}/FUZZ",
            "-json",
            "-w", wordlist,
            "-t", str(threads),
            "-timeout", str(timeout),
        ]

        if extensions:
            ext_str = ",".join(extensions)
            args.extend(["-e", ext_str])

        if match_codes:
            args.extend(["-mc", ",".join(map(str, match_codes))])

        if filter_codes:
            args.extend(["-fc", ",".join(map(str, filter_codes))])

        if recursive:
            args.append("-recursion")
            args.extend(["-recursion-depth", str(recursion_depth)])

        returncode, stdout, stderr = await self.execute(args, timeout=300)

        if returncode not in [0, 1]:  # 1 means matches found
            self.logger.warning(f"ffuf error: {stderr}")
            return []

        results = []
        for line in stdout.strip().split("\n"):
            if line and "{\"url\":" in line:
                try:
                    import json
                    data = json.loads(line)
                    results.append(Endpoint(
                        url=data.get("url", ""),
                        status_code=data.get("statuscode"),
                        content_length=data.get("length"),
                    ))
                except Exception as e:
                    self.logger.debug(f"Failed to parse result: {e}")

        return results


class NucleiTool(BaseTool):
    """Vulnerability scanner using Nuclei templates."""

    name = "nuclei"
    description = "Fast vulnerability scanner using templates"

    async def run(
        self,
        target: str,
        templates: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        rate_limit: int = 150,
        threads: int = 50,
        timeout: int = 5,
        json_output: bool = True,
        silent: bool = True,
    ) -> List[Vulnerability]:
        """Scan for vulnerabilities using Nuclei."""
        settings = self.settings.tools
        template_path = str(settings.nuclei_templates)

        args = ["nuclei", "-u", target]

        if templates:
            args.extend(["-t"] + templates)
        elif template_path:
            args.extend(["-t", template_path])

        if tags:
            args.extend(["-tags", ",".join(tags)])

        if severity:
            args.extend(["-severity", ",".join(severity)])

        args.extend(["-rate-limit", str(rate_limit)])
        args.extend(["-threads", str(threads)])
        args.extend(["-timeout", str(timeout)])

        if json_output:
            args.append("-json")
        if silent:
            args.append("-silent")

        returncode, stdout, stderr = await self.execute(args, timeout=600)

        if returncode not in [0, 1]:
            self.logger.warning(f"nuclei error: {stderr}")
            return []

        vulnerabilities = []
        for line in stdout.strip().split("\n"):
            if line and line.startswith("{"):
                try:
                    import json
                    data = json.loads(line)

                    vuln = Vulnerability(
                        name=data.get("info", {}).get("name", "Unknown"),
                        type=self._map_vuln_type(data.get("info", {}).get("tags", [])),
                        severity=self._map_severity(data.get("info", {}).get("severity", "info")),
                        target=data.get("host", target),
                        url=data.get("matched-at", target),
                        description=data.get("info", {}).get("description", ""),
                        cvss=data.get("info", {}).get("classification", {}).get("cvss-score"),
                        cve=data.get("info", {}).get("cve-id"),
                        cwe=data.get("info", {}).get("cwe-id"),
                        references=data.get("info", {}).get("reference", []),
                        tags=data.get("info", {}).get("tags", []),
                    )

                    # Generate PoC
                    if data.get("matcher-name"):
                        vuln.poc = f"nuclei -u {data.get('host')} -t {data.get('template')}"

                    vulnerabilities.append(vuln)
                except Exception as e:
                    self.logger.debug(f"Failed to parse vulnerability: {e}")

        return vulnerabilities

    def _map_vuln_type(self, tags: List[str]) -> VulnerabilityType:
        """Map Nuclei tags to vulnerability types."""
        tag_mapping = {
            "xss": VulnerabilityType.XSS,
            "sqli": VulnerabilityType.SQLI,
            "ssrf": VulnerabilityType.SSRF,
            "rce": VulnerabilityType.RCE,
            "idor": VulnerabilityType.IDOR,
            "redirect": VulnerabilityType.OPEN_REDIRECT,
            "csrf": VulnerabilityType.CSRF,
            "cors": VulnerabilityType.CORS,
            "xxe": VulnerabilityType.XXE,
            "lfi": VulnerabilityType.LFI,
            "rfi": VulnerabilityType.RFI,
            "path-traversal": VulnerabilityType.PATH_TRAVERSAL,
            "ssti": VulnerabilityType.SSTI,
            "command-injection": VulnerabilityType.COMMAND_INJECTION,
            "deserialization": VulnerabilityType.DESERIALIZATION,
        }

        for tag in tags:
            if tag.lower() in tag_mapping:
                return tag_mapping[tag.lower()]

        return VulnerabilityType.OTHER

    def _map_severity(self, severity: str) -> Severity:
        """Map Nuclei severity to our severity levels."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(severity.lower(), Severity.UNKNOWN)


class DalfoxTool(BaseTool):
    """XSS vulnerability scanner."""

    name = "dalfox"
    description = "Fast XSS vulnerability scanner"

    async def run(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        param: Optional[str] = None,
        blind_url: Optional[str] = None,
        mining: bool = True,
        dict_mining: bool = True,
        blind: bool = False,
        silient: bool = True,
    ) -> List[Vulnerability]:
        """Scan for XSS vulnerabilities."""
        args = ["dalfox", "url", url, "-o", "result.json"]

        if method.upper() == "POST":
            args.extend(["-d", data or ""])
            args.append("--data-method")

        if param:
            args.extend(["-p", param])

        if blind_url:
            args.extend(["-b", blind_url])

        if mining:
            args.append("--mining")
        if dict_mining:
            args.append("--dict-mining")
        if blind:
            args.append("--blind")

        if silient:
            args.append("--silient")

        returncode, stdout, stderr = await self.execute(args, timeout=300)

        if returncode not in [0, 1]:
            self.logger.warning(f"dalfox error: {stderr}")
            return []

        vulnerabilities = []

        for line in stdout.split("\n"):
            if "POC" in line or "VULN" in line:
                vuln = Vulnerability(
                    name="Cross-Site Scripting (XSS)",
                    type=VulnerabilityType.XSS,
                    severity=Severity.HIGH,
                    target=url,
                    url=url,
                    description="Potential XSS vulnerability detected",
                    poc=line.strip(),
                )
                vulnerabilities.append(vuln)

        return vulnerabilities


class ArjunTool(BaseTool):
    """HTTP parameter discovery tool."""

    name = "arjun"
    description = "HTTP parameter discovery tool"

    async def run(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        wordlist: Optional[str] = None,
        threads: int = 25,
        delay: float = 0,
        stable: bool = False,
        timeout: int = 30,
    ) -> List[str]:
        """Discover HTTP parameters."""
        args = [
            "arjun",
            "-u", url,
            "-oJ", "params.json",
            "-t", str(threads),
        ]

        if method.upper() != "GET":
            args.extend(["-m", method])

        if data:
            args.extend(["--post-data", data])

        if wordlist:
            args.extend(["-w", wordlist])

        if delay > 0:
            args.extend(["--delay", str(delay)])

        if stable:
            args.append("--stable")

        if timeout:
            args.extend(["--timeout", str(timeout)])

        returncode, stdout, stderr = await self.execute(args, timeout=300)

        if returncode != 0:
            self.logger.warning(f"arjun error: {stderr}")
            return []

        params = []
        try:
            import json
            with open("params.json") as f:
                data = json.load(f)
                if url in data:
                    params = list(data[url].keys())
        except Exception as e:
            self.logger.debug(f"Failed to parse params: {e}")

        return params


class ParamSpiderTool(BaseTool):
    """Parameter mining from web archives."""

    name = "paramspider"
    description = "Parameter mining from web archives"

    async def run(
        self,
        domain: str,
        level: int = 2,
        exclude: Optional[str] = None,
        output: Optional[str] = None,
    ) -> List[str]:
        """Mine parameters from web archives."""
        args = ["paramspider", "-d", domain, "-o", output or "params.txt"]

        if level > 1:
            args.extend(["--level", str(level)])

        if exclude:
            args.extend(["--exclude", exclude])

        returncode, stdout, stderr = await self.execute(args, timeout=120)

        if returncode != 0:
            self.logger.warning(f"paramspider error: {stderr}")
            return []

        params = []
        if output:
            try:
                with open(output) as f:
                    params = [line.strip() for line in f if line.strip()]
            except Exception:
                pass

        return params


class SqlmapTool(BaseTool):
    """SQL injection scanner."""

    name = "sqlmap"
    description = "Automatic SQL injection and database takeover tool"

    async def run(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        batch: bool = True,
        json_output: bool = True,
    ) -> List[Vulnerability]:
        """Scan for SQL injection vulnerabilities."""
        args = ["sqlmap", "-u", url]

        if method.upper() != "GET":
            args.extend(["--method", method])

        if data:
            args.extend(["--data", data])

        args.extend(["--level", str(level)])
        args.extend(["--risk", str(risk)])

        if batch:
            args.append("--batch")

        if json_output:
            args.extend(["--output-dir", "sqlmap_results"])
            args.append("--dump-format", "JSON")

        returncode, stdout, stderr = await self.execute(args, timeout=600)

        vulnerabilities = []

        if "is vulnerable" in stdout.lower() or "vulnerable" in stderr.lower():
            vuln = Vulnerability(
                name="SQL Injection",
                type=VulnerabilityType.SQLI,
                severity=Severity.CRITICAL,
                target=url,
                url=url,
                description="SQL injection vulnerability detected",
                poc=f"sqlmap -u {url}",
            )
            vulnerabilities.append(vuln)

        return vulnerabilities
