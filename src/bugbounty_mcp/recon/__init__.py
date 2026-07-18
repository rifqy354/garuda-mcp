"""Reconnaissance module for BugBounty MCP."""

from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..models import Endpoint, ScanResult, ScanStatus, Subdomain
from ..utils import BaseTool, HTTPClient, deduplicate_urls, format_curl, normalize_url


class SubfinderTool(BaseTool):
    """Passive subdomain enumeration using subfinder."""

    name = "subfinder"
    description = "Fast passive subdomain enumeration tool"

    async def run(
        self,
        domain: str,
        sources: Optional[List[str]] = None,
        all_sources: bool = False,
        silent: bool = True,
    ) -> List[Subdomain]:
        """Enumerate subdomains for a domain."""
        args = ["subfinder", "-d", domain, "-o", "-json"]

        if all_sources:
            args.append("-all")
        elif sources:
            args.extend(["-sources"] + sources)

        if silent:
            args.append("-silent")

        returncode, stdout, stderr = await self.execute(args, timeout=120)

        if returncode != 0:
            self.logger.warning(f"subfinder error: {stderr}")
            return []

        subdomains = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    import json
                    data = json.loads(line)
                    subdomains.append(Subdomain(
                        domain=data.get("host", data.get("domain", "")),
                        cname=data.get("cname", [None])[0] if data.get("cname") else None,
                    ))
                except Exception as e:
                    self.logger.debug(f"Failed to parse subdomain: {e}")

        return subdomains


class HttpxTool(BaseTool):
    """Fast HTTP probe tool for alive host discovery."""

    name = "httpx"
    description = "Fast HTTP probe and technology detection tool"

    async def run(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        threads: int = 50,
        follow_redirects: bool = True,
        store_response: bool = False,
        silent: bool = True,
    ) -> List[Endpoint]:
        """Probe targets and detect alive hosts."""
        from datetime import datetime

        args = ["httpx", "-json", "-list", "-"]

        if ports:
            args.extend(["-ports", ",".join(map(str, ports))])

        args.extend(["-threads", str(threads)])

        if follow_redirects:
            args.append("-follow-redirects")

        if store_response:
            args.append("-store-response")

        if silent:
            args.append("-silent")

        # Run httpx with input from targets
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        input_data = "\n".join(targets)
        stdout, stderr = await proc.communicate(
            input_data.encode() if input_data else None,
            timeout=120,
        )

        if proc.returncode != 0:
            self.logger.warning(f"httpx error: {stderr.decode()}")
            return []

        endpoints = []
        for line in stdout.decode().strip().split("\n"):
            if line:
                try:
                    import json
                    data = json.loads(line)
                    endpoint = Endpoint(
                        url=data.get("url", ""),
                        status_code=data.get("status_code"),
                        content_length=data.get("content_length"),
                        title=data.get("title"),
                        technologies=data.get("technologies", []),
                        headers=data.get("header", {}),
                    )
                    endpoints.append(endpoint)
                except Exception as e:
                    self.logger.debug(f"Failed to parse endpoint: {e}")

        return endpoints


class NaabuTool(BaseTool):
    """Fast port scanner."""

    name = "naabu"
    description = "Fast port scanner using naabu"

    async def run(
        self,
        host: str,
        ports: Optional[str] = None,
        top_ports: Optional[int] = None,
        rate: int = 1000,
        silent: bool = True,
    ) -> List[int]:
        """Scan ports on a host."""
        args = ["naabu", "-host", host, "-json"]

        if ports:
            args.extend(["-ports", ports])
        elif top_ports:
            args.extend(["-top-ports", str(top_ports)])

        args.extend(["-rate", str(rate)])

        if silent:
            args.append("-silent")

        returncode, stdout, stderr = await self.execute(args, timeout=300)

        if returncode != 0:
            self.logger.warning(f"naabu error: {stderr}")
            return []

        open_ports = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    import json
                    data = json.loads(line)
                    if data.get("port"):
                        open_ports.append(data["port"])
                except Exception:
                    pass

        return open_ports


class KatanaTool(BaseTool):
    """Fast web crawler."""

    name = "katana"
    description = "Fast web crawler for endpoint discovery"

    async def run(
        self,
        url: str,
        depth: int = 3,
        max_pages: int = 100,
        js_crawl: bool = True,
        form_extraction: bool = True,
        silent: bool = True,
    ) -> List[Endpoint]:
        """Crawl a URL and discover endpoints."""
        args = [
            "katana",
            "-u", url,
            "-json",
            "-depth", str(depth),
            "-max-count", str(max_pages),
        ]

        if js_crawl:
            args.append("-jc")

        if form_extraction:
            args.append("-forms")

        if silent:
            args.append("-silent")

        returncode, stdout, stderr = await self.execute(args, timeout=300)

        if returncode != 0:
            self.logger.warning(f"katana error: {stderr}")
            return []

        endpoints = []
        seen_urls = set()

        for line in stdout.strip().split("\n"):
            if line:
                try:
                    import json
                    data = json.loads(line)
                    url = data.get("url", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        endpoints.append(Endpoint(
                            url=url,
                            method=data.get("method", "GET"),
                        ))
                except Exception as e:
                    self.logger.debug(f"Failed to parse endpoint: {e}")

        return endpoints


class GauTool(BaseTool):
    """Get All URLs from web archives."""

    name = "gau"
    description = "Get All URLs from web archives"

    async def run(
        self,
        domain: str,
        providers: Optional[List[str]] = None,
        include_subs: bool = True,
        blacklist: Optional[str] = None,
        silent: bool = True,
    ) -> List[str]:
        """Get historical URLs for a domain."""
        args = ["gau", domain, "--json"]

        if providers:
            args.extend(["--providers", ",".join(providers)])

        if include_subs:
            args.append("--subs")

        if blacklist:
            args.extend(["--blacklist", blacklist])

        if silent:
            args.append("--silent")

        returncode, stdout, stderr = await self.execute(args, timeout=120)

        if returncode != 0:
            self.logger.warning(f"gau error: {stderr}")
            return []

        urls = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    import json
                    data = json.loads(line)
                    url = data.get("url", "")
                    if url:
                        urls.append(url)
                except Exception:
                    pass

        return deduplicate_urls(urls)


class WaybackurlsTool(BaseTool):
    """Get URLs from Wayback Machine."""

    name = "waybackurls"
    description = "Get URLs from Wayback Machine"

    async def run(
        self,
        domain: str,
        get_versions: bool = False,
        no_subs: bool = False,
    ) -> List[str]:
        """Get historical URLs from Wayback Machine."""
        args = ["waybackurls", domain]

        if get_versions:
            args.append("-get-versions")

        if no_subs:
            args.append("-no-subs")

        returncode, stdout, stderr = await self.execute(args, timeout=60)

        if returncode != 0:
            self.logger.warning(f"waybackurls error: {stderr}")
            return []

        return stdout.strip().split("\n")


class DnsxTool(BaseTool):
    """Fast DNS toolkit."""

    name = "dnsx"
    description = "Fast DNS toolkit for DNS queries"

    async def run(
        self,
        domain: str,
        query_type: str = "A",
        wordlist: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Perform DNS queries."""
        args = ["dnsx", "-d", domain, "-qtype", query_type, "-json"]

        if wordlist:
            args.extend(["-w", wordlist, "-a"])  # -a for automated output

        returncode, stdout, stderr = await self.execute(args, timeout=60)

        if returncode != 0:
            self.logger.warning(f"dnsx error: {stderr}")
            return []

        results = []
        for line in stdout.strip().split("\n"):
            if line:
                try:
                    import json
                    results.append(json.loads(line))
                except Exception:
                    pass

        return results


# Import asyncio for subprocess
import asyncio
