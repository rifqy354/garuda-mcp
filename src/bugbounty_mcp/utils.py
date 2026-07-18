"""Base classes and utilities for BugBounty MCP."""

import asyncio
import hashlib
import json
import logging
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, TypeVar

import aiofiles
import httpx

from .config import get_settings
from .models import ScanResult, ScanStatus

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=ScanResult)


class ToolError(Exception):
    """Exception raised when a tool execution fails."""

    def __init__(self, tool: str, message: str, stderr: str = ""):
        self.tool = tool
        self.message = message
        self.stderr = stderr
        super().__init__(f"{tool}: {message}")


class BaseTool(ABC):
    """Base class for all security tools."""

    name: str
    description: str
    version: Optional[str] = None

    def __init__(self):
        self.settings = get_settings()
        self.logger = logging.getLogger(f"bugbounty.{self.name}")

    @abstractmethod
    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Run the tool with given arguments."""
        pass

    def is_installed(self) -> bool:
        """Check if the tool is installed."""
        try:
            result = subprocess.run(
                ["which", self.name],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False

    async def execute(
        self,
        command: List[str],
        timeout: int = 60,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> tuple[int, str, str]:
        """
        Execute a command and return (returncode, stdout, stderr).

        This method properly handles command execution without shell=True
        to prevent command injection vulnerabilities.
        """
        self.logger.debug(f"Executing: {' '.join(command)}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout,
                )
                return (
                    proc.returncode,
                    stdout.decode("utf-8", errors="replace"),
                    stderr.decode("utf-8", errors="replace"),
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise ToolError(
                    self.name,
                    f"Command timed out after {timeout} seconds"
                )

        except FileNotFoundError:
            raise ToolError(
                self.name,
                f"Command not found: {command[0]}"
            )
        except Exception as e:
            raise ToolError(self.name, str(e))

    async def execute_json(
        self,
        command: List[str],
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Execute command and parse JSON output."""
        returncode, stdout, stderr = await self.execute(command, timeout)

        if returncode != 0:
            raise ToolError(self.name, f"Command failed: {stderr}", stderr)

        try:
            return json.loads(stdout)
        except json.JSONDecodeError as e:
            raise ToolError(
                self.name,
                f"Failed to parse JSON output: {e}",
                stdout
            )


class AsyncToolRunner:
    """Run multiple tools concurrently."""

    def __init__(self, max_concurrent: int = 5):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results: List[ScanResult] = []

    async def run_tool(
        self,
        tool: BaseTool,
        *args: Any,
        **kwargs: Any
    ) -> ScanResult:
        """Run a single tool with concurrency limiting."""
        async with self.semaphore:
            from datetime import datetime

            result = ScanResult(
                scan_id=hashlib.md5(
                    f"{tool.name}:{datetime.utcnow().isoformat()}".encode()
                ).hexdigest()[:8],
                tool=tool.name,
                target=str(kwargs.get("target", "")),
                status=ScanStatus.RUNNING,
                started_at=datetime.utcnow(),
            )

            try:
                output = await tool.run(*args, **kwargs)
                result.status = ScanStatus.COMPLETED
                result.raw_output = str(output) if output else ""
            except ToolError as e:
                result.status = ScanStatus.FAILED
                result.errors.append(str(e))
            except Exception as e:
                result.status = ScanStatus.FAILED
                result.errors.append(f"Unexpected error: {e}")
            finally:
                from datetime import datetime
                result.completed_at = datetime.utcnow()
                if result.started_at and result.completed_at:
                    result.duration_seconds = (
                        result.completed_at - result.started_at
                    ).total_seconds()

            return result


class HTTPClient:
    """Async HTTP client for web interactions."""

    def __init__(self, timeout: int = 30):
        self.client: Optional[httpx.AsyncClient] = None
        self.timeout = timeout

    async def __aenter__(self) -> "HTTPClient":
        """Enter async context."""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,  # For security testing
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context."""
        if self.client:
            await self.client.aclose()

    async def request(
        self,
        method: str,
        url: str,
        **kwargs: Any
    ) -> httpx.Response:
        """Make an HTTP request."""
        if not self.client:
            raise RuntimeError("HTTPClient not initialized. Use 'async with'.")
        return await self.client.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Make a GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(
        self,
        url: str,
        **kwargs: Any
    ) -> httpx.Response:
        """Make a POST request."""
        return await self.request("POST", url, **kwargs)


def calculate_cvss(severity: str, impact: str = "partial") -> float:
    """Calculate CVSS score from severity."""
    severity_scores = {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
        "info": 0.0,
    }
    return severity_scores.get(severity.lower(), 0.0)


def format_curl(method: str, url: str, headers: Dict[str, str] = None,
                 data: str = None) -> str:
    """Format a cURL command from request details."""
    parts = ["curl"]

    if headers:
        for key, value in headers.items():
            parts.extend(["-H", f"'{key}: {value}'"])

    if data:
        parts.extend(["-d", f"'{data}'"])

    parts.extend(["-X", method])
    parts.append(f"'{url}'")

    return " ".join(parts)


async def save_json(data: Any, filepath: Path) -> None:
    """Save data as JSON file."""
    async with aiofiles.open(filepath, "w") as f:
        await f.write(json.dumps(data, indent=2, default=str))


async def load_json(filepath: Path) -> Any:
    """Load data from JSON file."""
    async with aiofiles.open(filepath) as f:
        content = await f.read()
        return json.loads(content)


def deduplicate_urls(urls: List[str]) -> List[str]:
    """Remove duplicate URLs while preserving order."""
    seen = set()
    result = []
    for url in urls:
        normalized = url.rstrip("/").lower()
        if normalized not in seen:
            seen.add(normalized)
            result.append(url)
    return result


def normalize_url(url: str) -> str:
    """Normalize URL format."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")
