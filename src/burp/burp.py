"""Burp Suite integration module for BugBounty MCP."""

from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..models import Endpoint, ScanStatus, ScanResult, Severity, Vulnerability, VulnerabilityType
from ..utils import BaseTool, HTTPClient


class BurpAPIError(Exception):
    """Exception for Burp API errors."""

    pass


class BurpClient:
    """Client for Burp Suite Professional REST API."""

    def __init__(self):
        self.settings = get_settings().burp
        self.base_url = self.settings.base_url
        self.api_key = self.settings.api_key
        self.client: Optional[HTTPClient] = None

    async def __aenter__(self) -> "BurpClient":
        """Enter async context."""
        self.client = HTTPClient(timeout=60)
        await self.client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        if self.client:
            await self.client.__aexit__(*args)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with API key."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _get(self, endpoint: str) -> Dict[str, Any]:
        """Make GET request to Burp API."""
        if not self.client:
            raise RuntimeError("BurpClient not initialized")

        url = f"{self.base_url}{endpoint}"
        response = await self.client.get(url, headers=self._get_headers())

        if response.status_code != 200:
            raise BurpAPIError(f"Burp API error: {response.status_code}")

        return response.json()

    async def _post(
        self,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make POST request to Burp API."""
        if not self.client:
            raise RuntimeError("BurpClient not initialized")

        url = f"{self.base_url}{endpoint}"
        response = await self.client.post(
            url,
            json=data or {},
            headers=self._get_headers()
        )

        if response.status_code not in [200, 201]:
            raise BurpAPIError(f"Burp API error: {response.status_code}")

        return response.json()

    async def get_sitemap(self, base_url: Optional[str] = None) -> List[Endpoint]:
        """Get sitemap from Burp."""
        from datetime import datetime

        data = await self._get("/sitemap")

        endpoints = []
        for item in data.get("items", []):
            if base_url and not item.get("url", "").startswith(base_url):
                continue

            endpoints.append(Endpoint(
                url=item.get("url", ""),
                status_code=item.get("status_code"),
                method=item.get("method", "GET"),
            ))

        return endpoints

    async def get_issues(self) -> List[Vulnerability]:
        """Get scan issues from Burp."""
        data = await self._get("/scan/issues")

        vulnerabilities = []
        for issue in data.get("issues", []):
            vuln = Vulnerability(
                name=issue.get("name", "Unknown"),
                type=self._map_issue_type(issue.get("type", "")),
                severity=self._map_severity(issue.get("severity", "info")),
                target=issue.get("host", ""),
                url=issue.get("url", ""),
                description=issue.get("description", ""),
                remediation=issue.get("remediation", ""),
                cvss=issue.get("cvss_score"),
                references=[
                    ref.get("url", "")
                    for ref in issue.get("references", [])
                ],
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    async def run_passive_scan(self, base_url: str) -> str:
        """Start a passive scan on a URL."""
        data = await self._post("/scan", {
            "urls": [base_url],
            "scope": {
                "include": [{"url": base_url}],
                "exclude": []
            }
        })
        return data.get("scan_id", "")

    async def run_active_scan(
        self,
        base_url: str,
        insertion_point: Optional[str] = None,
    ) -> str:
        """Start an active scan on a URL."""
        payload = {
            "urls": [base_url],
            "scope": {
                "include": [{"url": base_url}],
                "exclude": []
            }
        }

        if insertion_point:
            payload["insertion_point"] = insertion_point

        data = await self._post("/scan", payload)
        return data.get("scan_id", "")

    async def get_scan_status(self, scan_id: str) -> str:
        """Get scan status."""
        data = await self._get(f"/scan/{scan_id}/status")
        return data.get("status", "unknown")

    async def add_to_scope(self, url: str) -> None:
        """Add URL to Burp scope."""
        await self._post("/scope/include", {"url": url})

    async def remove_from_scope(self, url: str) -> None:
        """Remove URL from Burp scope."""
        await self._post("/scope/exclude", {"url": url})

    async def send_to_repeater(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send request to Repeater."""
        data = await self._post("/repeater", {
            "url": url,
            "method": method,
            "headers": headers or {},
            "body": body or "",
        })
        return data

    async def export_report(self, format: str = "html") -> bytes:
        """Export scan report."""
        data = await self._post("/report", {"format": format})
        return data.get("report", "").encode()

    def _map_issue_type(self, issue_type: str) -> VulnerabilityType:
        """Map Burp issue type to our vulnerability type."""
        type_mapping = {
            "xss": VulnerabilityType.XSS,
            "sql": VulnerabilityType.SQLI,
            "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
            "ssrf": VulnerabilityType.SSRF,
            "open_redirect": VulnerabilityType.OPEN_REDIRECT,
            "csrf": VulnerabilityType.CSRF,
        }

        for key, value in type_mapping.items():
            if key in issue_type.lower():
                return value

        return VulnerabilityType.OTHER

    def _map_severity(self, severity: str) -> Severity:
        """Map Burp severity to our severity."""
        mapping = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return mapping.get(severity.lower(), Severity.UNKNOWN)


class BurpTool(BaseTool):
    """Wrapper for Burp Suite integration."""

    name = "burp"
    description = "Burp Suite Professional API integration"

    async def run_passive_scan(self, url: str) -> List[Vulnerability]:
        """Run passive scan on URL."""
        async with BurpClient() as client:
            scan_id = await client.run_passive_scan(url)

            # Poll for completion
            import asyncio
            for _ in range(60):  # 5 minutes max
                await asyncio.sleep(5)
                status = await client.get_scan_status(scan_id)

                if status == "completed":
                    break

            return await client.get_issues()

    async def run_active_scan(self, url: str) -> List[Vulnerability]:
        """Run active scan on URL."""
        async with BurpClient() as client:
            scan_id = await client.run_active_scan(url)

            # Poll for completion
            import asyncio
            for _ in range(120):  # 10 minutes max
                await asyncio.sleep(5)
                status = await client.get_scan_status(scan_id)

                if status == "completed":
                    break

            return await client.get_issues()

    async def get_sitemap(self, base_url: Optional[str] = None) -> List[Endpoint]:
        """Get Burp sitemap."""
        async with BurpClient() as client:
            return await client.get_sitemap(base_url)

    async def send_repeater(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send request to Repeater."""
        async with BurpClient() as client:
            return await client.send_to_repeater(url, method, headers, body)

    async def manage_scope(
        self,
        url: str,
        action: str = "add"
    ) -> bool:
        """Manage Burp scope."""
        async with BurpClient() as client:
            if action == "add":
                await client.add_to_scope(url)
            elif action == "remove":
                await client.remove_from_scope(url)
            else:
                return False
            return True
