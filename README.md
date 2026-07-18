# BugBounty MCP Server

A modern, modular MCP server for bug bounty hunting and security research.

## Features

- **Recon Module** - Subdomain enumeration, port scanning, URL discovery
- **Web Module** - Fuzzing, vulnerability scanning, parameter discovery
- **API Module** - REST/GraphQL testing, OpenAPI analysis
- **Burp Integration** - Passive/active scanning, repeater, scope management
- **Ghidra Integration** - Binary analysis, decompilation, reverse engineering
- **Mobile Module** - APK analysis, iOS research
- **Binary Module** - Checksec, ROP gadgets, string analysis
- **AI Orchestrator** - Intelligent workflow automation
- **Reporting** - Auto-generate Markdown/HTML/PDF reports

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Claude Code                          │
│                     VSCode / Cursor                         │
└─────────────────────────────────────────────────────────────┘
                              │ MCP
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      BugBounty MCP Server                    │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐   │
│  │  Recon  │ │   Web   │ │   API   │ │     Burp        │   │
│  │         │ │         │ │         │ │                 │   │
│  │•subfinder│ │•ffuf   │ │•graphql │ │•passive_scan   │   │
│  │•httpx   │ │•nuclei  │ │•openapi │ │•active_scan    │   │
│  │•naabu   │ │•dalfox  │ │•jwt     │ │•repeater       │   │
│  │•katana  │ │•sqlmap  │ │•rest    │ │•scope          │   │
│  │•gau     │ │•arjun   │ │         │ │                 │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────────────┐   │
│  │ Ghidra  │ │ Binary  │ │ Mobile  │ │     AI          │   │
│  │         │ │         │ │         │ │                 │   │
│  │•analyze │ │•checksec│ │•jadx    │ │•workflow        │   │
│  │•decompile│ │•ropgadget│ │•apktool│ │•recommend      │   │
│  │•strings │ │•objdump │ │•frida   │ │•prioritize      │   │
│  │•xrefs   │ │•strings │ │•classdump│ │                 │   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  Reporting Module                     │    │
│  │         Markdown / HTML / PDF / JSON                 │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Tech Stack

- **FastMCP** - MCP framework
- **Pydantic** - Data validation
- **AsyncIO** - Concurrent execution
- **ProjectDiscovery Tools** - Recon foundation
- **Burp Suite Professional API** - Web testing
- **Ghidra Headless** - Binary analysis
- **SQLite** - Results caching
- **Docker Compose** - Easy deployment

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Burp Suite Professional (for Burp integration)
- Ghidra (for reverse engineering)
- Go 1.21+ (for ProjectDiscovery tools)

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/bugbounty-mcp.git
cd bugbounty-mcp

# Install Python dependencies
pip install -e .

# Build Docker containers
docker-compose build

# Run the MCP server
python -m bugbounty_mcp.server
```

### Configuration

Copy and edit the config file:

```bash
cp config/config.yaml.example config/config.yaml
```

Edit `config/config.yaml`:

```yaml
mcp:
  host: "0.0.0.0"
  port: 8765

burp:
  host: "localhost"
  port: 1337
  api_key: "your-burp-api-key"

ghidra:
  install_path: "/opt/ghidra"
  projects_dir: "/tmp/ghidra_projects"

tools:
  projectdiscovery:
    install_path: "/opt/pdtm"
  nuclei:
    templates: "/opt/nuclei-templates"
```

## Usage with Claude Code

Add to your `~/.config/claude/code.json`:

```json
{
  "mcpServers": {
    "bugbounty": {
      "command": "python",
      "args": ["-m", "bugbounty_mcp.server"],
      "env": {
        "PYTHONPATH": "/path/to/bugbounty-mcp"
      }
    }
  }
}
```

## Available Tools

### Recon Module

| Tool | Description |
|------|-------------|
| `subdomain_enum` | Passive subdomain enumeration |
| `port_scan` | Fast port scanning with naabu |
| `probe_urls` | HTTP probing with httpx |
| `crawl_urls` | Web crawling with katana |
| `url_discovery` | Historical URL discovery |
| `dns_enum` | DNS enumeration |

### Web Module

| Tool | Description |
|------|-------------|
| `web_fuzz` | Directory/parameter fuzzing |
| `vuln_scan` | Vulnerability scanning with Nuclei |
| `xss_scan` | XSS detection |
| `sql_scan` | SQL injection testing |
| `param_discovery` | HTTP parameter discovery |

### API Module

| Tool | Description |
|------|-------------|
| `graphql_test` | GraphQL security testing |
| `openapi_analyze` | OpenAPI/Swagger analysis |
| `jwt_analyze` | JWT token analysis |
| `rest_fuzz` | REST API fuzzing |

### Burp Integration

| Tool | Description |
|------|-------------|
| `burp_passive_scan` | Run passive scan |
| `burp_active_scan` | Run active scan on target |
| `burp_repeater` | Send custom request |
| `burp_scope` | Manage target scope |
| `burp_sitemap` | Get sitemap |
| `burp_export` | Export findings |

### Ghidra Integration

| Tool | Description |
|------|-------------|
| `ghidra_analyze` | Analyze binary |
| `ghidra_decompile` | Decompile function |
| `ghidra_strings` | Extract strings |
| `ghidra_functions` | List functions |
| `ghidra_xrefs` | Cross references |
| `ghidra_imports` | List imports |

### Binary Module

| Tool | Description |
|------|-------------|
| `checksec` | Check security features |
| `rop_gadgets` | Find ROP gadgets |
| `one_gadget` | Find one-gadget RCE |
| `binary_strings` | Extract strings |
| `elf_analysis` | ELF binary analysis |

### Mobile Module

| Tool | Description |
|------|-------------|
| `apk_decompile` | Decompile Android APK |
| `apk_analyze` | Static APK analysis |
| `ios_classdump` | Dump Objective-C classes |

### Reporting Module

| Tool | Description |
|------|-------------|
| `generate_report` | Generate vulnerability report |
| `export_json` | Export findings as JSON |
| `export_markdown` | Export as Markdown |

## Example Sessions

### Recon on a Target

```
You: "Do recon on swisspost.com"

MCP:
1. subfinder -d swisspost.com
2. httpx -l subdomains.txt -ports 80,443
3. katana -list alive_urls.txt
4. nuclei -list targets.txt
```

### Binary Analysis

```
You: "Analyze the binary /tmp/vuln"

MCP:
1. checksec /tmp/vuln
2. ghidra_analyze /tmp/vuln
3. ghidra_decompile main
4. ropgadget /tmp/vuln
```

### Web Vulnerability Scan

```
You: "Scan https://target.com for vulnerabilities"

MCP:
1. ffuf -u https://target.com/FUZZ
2. nuclei -t cves -u https://target.com
3. dalfox url https://target.com
4. arjun -u https://target.com
```

## Development

### Run Tests

```bash
pytest tests/ -v
```

### Type Checking

```bash
mypy src/
```

### Format Code

```bash
ruff format src/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE)

## Roadmap

- [ ] Core MCP server with basic tools
- [ ] Burp Suite integration
- [ ] Ghidra integration
- [ ] AI workflow orchestrator
- [ ] Mobile analysis module
- [ ] Advanced reporting
- [ ] Web UI for results

---

**Note**: This project is for educational and authorized security testing purposes only.
