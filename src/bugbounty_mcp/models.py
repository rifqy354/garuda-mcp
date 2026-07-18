"""Data models and types for BugBounty MCP."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class VulnerabilityType(str, Enum):
    """Common vulnerability types."""

    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    RCE = "rce"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    CORS = "cors"
    SSTI = "ssti"
    XXE = "xxe"
    LFI = "lfi"
    RFI = "rfi"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    DESERIALIZATION = "deserialization"
    BUSINESS_LOGIC = "business_logic"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OTHER = "other"


class ScanStatus(str, Enum):
    """Scan status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Target(BaseModel):
    """Represents a target for testing."""

    url: HttpUrl
    host: Optional[str] = None
    port: Optional[int] = None
    scheme: Optional[str] = None
    path: Optional[str] = None
    is_scope: bool = True

    @classmethod
    def from_url(cls, url: str) -> "Target":
        """Create Target from URL string."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return cls(
            url=url,
            host=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            scheme=parsed.scheme,
            path=parsed.path,
        )

    model_config = {"extra": "ignore"}


class Endpoint(BaseModel):
    """Represents a discovered endpoint."""

    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    content_length: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"extra": "ignore"}


class Subdomain(BaseModel):
    """Represents a discovered subdomain."""

    domain: str
    ip: Optional[str] = None
    cname: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    alive: bool = True
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    model_config = {"extra": "ignore"}


class Vulnerability(BaseModel):
    """Represents a discovered vulnerability."""

    id: Optional[str] = None
    name: str
    type: VulnerabilityType = VulnerabilityType.OTHER
    severity: Severity = Severity.INFO
    target: str
    url: Optional[str] = None
    description: str
    impact: Optional[str] = None
    remediation: Optional[str] = None
    cvss: Optional[float] = None
    cve: Optional[str] = None
    cwe: Optional[str] = None
    poc: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    curl_command: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    status: ScanStatus = ScanStatus.PENDING

    def to_markdown(self) -> str:
        """Convert to Markdown format."""
        lines = [
            f"## {self.name}",
            f"",
            f"**Severity:** {self.severity.value.upper()}",
            f"**Type:** {self.type.value}",
            f"**Target:** {self.target}",
        ]

        if self.cvss:
            lines.append(f"**CVSS:** {self.cvss}")

        if self.cve:
            lines.append(f"**CVE:** {self.cve}")

        lines.extend([
            f"",
            f"### Description",
            f"",
            self.description,
        ])

        if self.impact:
            lines.extend([
                f"",
                f"### Impact",
                f"",
                self.impact,
            ])

        if self.remediation:
            lines.extend([
                f"",
                f"### Remediation",
                f"",
                self.remediation,
            ])

        if self.poc:
            lines.extend([
                f"",
                f"### Proof of Concept",
                f"",
                f"```",
                self.poc,
                f"```",
            ])

        return "\n".join(lines)

    model_config = {"extra": "ignore"}


class ScanResult(BaseModel):
    """Result from a scan operation."""

    scan_id: str
    tool: str
    target: str
    status: ScanStatus
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    endpoints: List[Endpoint] = Field(default_factory=list)
    subdomains: List[Subdomain] = Field(default_factory=list)
    raw_output: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    model_config = {"extra": "ignore"}


class BinaryInfo(BaseModel):
    """Information about a binary file."""

    path: str
    file_type: Optional[str] = None
    architecture: Optional[str] = None
    linker: Optional[str] = None
    stripped: bool = False
    pie: bool = False
    canary: bool = False
    nx: bool = False
    relro: Optional[str] = None
    rpath: Optional[str] = None
    runpath: Optional[str] = None
    static: bool = False
    size: Optional[int] = None
    md5: Optional[str] = None
    sha256: Optional[str] = None

    model_config = {"extra": "ignore"}


class Function(BaseModel):
    """Represents a function in a binary."""

    name: str
    address: str
    signature: Optional[str] = None
    decompiled_code: Optional[str] = None
    calling_convention: Optional[str] = None
    local_variables: List[str] = Field(default_factory=list)
    xrefs: List[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StringEntry(BaseModel):
    """Represents a string found in a binary."""

    address: str
    value: str
    length: int
    is_unicode: bool = False

    model_config = {"extra": "ignore"}


class Report(BaseModel):
    """Vulnerability report."""

    title: str
    target: str
    scope: List[str] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    author: Optional[str] = None
    version: str = "1.0"

    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics."""
        summary = {
            "total": len(self.vulnerabilities),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for vuln in self.vulnerabilities:
            key = vuln.severity.value
            if key in summary:
                summary[key] += 1

        self.summary = summary
        return summary

    model_config = {"extra": "ignore"}
