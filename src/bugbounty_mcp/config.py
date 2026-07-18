"""Configuration management for BugBounty MCP."""

from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class MCPConfig(BaseSettings):
    """MCP server configuration."""

    host: str = Field(default="0.0.0.0", description="Host to bind to")
    port: int = Field(default=8765, ge=1, le=65535, description="Port to listen on")

    model_config = SettingsConfigDict(env_prefix="MCP_")


class BurpConfig(BaseSettings):
    """Burp Suite Professional API configuration."""

    host: str = Field(default="localhost", description="Burp API host")
    port: int = Field(default=1337, ge=1, le=65535, description="Burp API port")
    api_key: Optional[str] = Field(default=None, description="Burp API key")

    @property
    def base_url(self) -> str:
        """Get the Burp API base URL."""
        return f"http://{self.host}:{self.port}/v0"

    @property
    def is_configured(self) -> bool:
        """Check if Burp is configured."""
        return self.host != "disabled"

    model_config = SettingsConfigDict(env_prefix="BURP_")


class GhidraConfig(BaseSettings):
    """Ghidra installation configuration."""

    install_path: Path = Field(
        default=Path("/opt/ghidra"),
        description="Ghidra installation path"
    )
    projects_dir: Path = Field(
        default=Path("/tmp/ghidra_projects"),
        description="Directory for Ghidra projects"
    )
    headless_path: Optional[Path] = Field(
        default=None,
        description="Path to Ghidra headless analyzer"
    )

    @field_validator("install_path", "projects_dir")
    @classmethod
    def validate_paths(cls, v: Path) -> Path:
        """Ensure paths are absolute."""
        if not v.is_absolute():
            raise ValueError(f"Path must be absolute: {v}")
        return v

    @property
    def is_installed(self) -> bool:
        """Check if Ghidra is installed."""
        return self.install_path.exists()

    model_config = SettingsConfigDict(env_prefix="GHIDRA_")


class ToolsConfig(BaseSettings):
    """Security tools configuration."""

    projectdiscovery_path: Path = Field(
        default=Path("/opt/pdtm"),
        description="ProjectDiscovery tools installation path"
    )
    nuclei_templates: Path = Field(
        default=Path("/opt/nuclei-templates"),
        description="Nuclei templates directory"
    )
    wordlists: Path = Field(
        default=Path("/usr/share/wordlists"),
        description="Wordlists directory"
    )

    model_config = SettingsConfigDict(env_prefix="TOOLS_")


class DatabaseConfig(BaseSettings):
    """Database configuration."""

    path: Path = Field(
        default=Path("/tmp/bugbounty_mcp.db"),
        description="SQLite database path"
    )

    model_config = SettingsConfigDict(env_prefix="DB_")


class Settings(BaseSettings):
    """Main settings class combining all configurations."""

    mcp: MCPConfig = Field(default_factory=MCPConfig)
    burp: BurpConfig = Field(default_factory=BurpConfig)
    ghidra: GhidraConfig = Field(default_factory=GhidraConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)

    debug: bool = Field(default=False, description="Enable debug mode")
    verbose: bool = Field(default=False, description="Enable verbose output")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @classmethod
    def from_config_file(cls, config_path: Path) -> "Settings":
        """Load settings from a YAML config file."""
        import yaml

        if not config_path.exists():
            return cls()

        with open(config_path) as f:
            config_data = yaml.safe_load(f)

        return cls(**config_data)


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def init_settings(config_path: Optional[Path] = None) -> Settings:
    """Initialize settings from optional config file."""
    global _settings

    if config_path and config_path.exists():
        _settings = Settings.from_config_file(config_path)
    else:
        _settings = Settings()

    return _settings
