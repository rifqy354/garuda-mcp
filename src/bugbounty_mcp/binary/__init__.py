"""Binary analysis module for BugBounty MCP."""

import asyncio
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import BinaryInfo, StringEntry
from ..utils import BaseTool


class ChecksecTool(BaseTool):
    """Check security features of binary files."""

    name = "checksec"
    description = "Check security features of binary files"

    async def run(self, binary_path: str) -> BinaryInfo:
        """Check security features of a binary."""
        if not Path(binary_path).exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        # Use readelf for ELF files
        if self._is_elf(binary_path):
            return await self._check_elf(binary_path)

        # Use otool for Mach-O files
        elif self._is_macho(binary_path):
            return await self._check_macho(binary_path)

        # Generic check
        return BinaryInfo(
            path=binary_path,
            file_type="unknown",
        )

    def _is_elf(self, path: str) -> bool:
        """Check if file is ELF."""
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                return magic[:4] == b"\\x7fELF"
        except Exception:
            return False

    def _is_macho(self, path: str) -> bool:
        """Check if file is Mach-O."""
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                return magic in [b"\\xfe\\xed\\xfa\\xce", b"\\xce\\xfa\\xed\\xfe",
                                 b"\\xfe\\xed\\xfa\\xcf", b"\\xcf\\xfa\\xed\\xfe"]
        except Exception:
            return False

    async def _check_elf(self, binary_path: str) -> BinaryInfo:
        """Check ELF binary security features."""
        info = BinaryInfo(path=binary_path)

        # Get file info
        returncode, stdout, _ = await self.execute(
            ["file", "-b", binary_path],
            timeout=10
        )
        info.file_type = stdout.strip()

        # Get hashes
        with open(binary_path, "rb") as f:
            data = f.read()
            info.md5 = hashlib.md5(data).hexdigest()
            info.sha256 = hashlib.sha256(data).hexdigest()
            info.size = len(data)

        # Get readelf info
        returncode, stdout, _ = await self.execute(
            ["readelf", "-h", binary_path],
            timeout=10
        )

        for line in stdout.split("\n"):
            line = line.strip()

            if "Machine:" in line:
                info.architecture = line.split("Machine:")[1].strip()

            if "Entry point address:" in line:
                addr = line.split("Entry point address:")[1].strip()
                # Check if PIE
                if "0x0" in addr:
                    info.pie = True

            if "Type:" in line:
                reloc = line.split("Type:")[1].strip()
                if "DYN" in reloc:
                    info.pie = True

        # Get security features
        returncode, stdout, _ = await self.execute(
            ["readelf", "-l", binary_path],
            timeout=10
        )

        info.nx = False
        info.relro = "no"

        for line in stdout.split("\n"):
            if "GNU_STACK" in line:
                if "RWE" in line:
                    info.nx = False
                elif "RW" in line:
                    info.nx = True

        # Get RELRO info
        returncode, stdout, _ = await self.execute(
            ["readelf", "-d", binary_path],
            timeout=10
        )

        if "BIND_NOW" in stdout:
            info.relro = "full"
        elif "RELRO" in stdout:
            info.relro = "partial"
        else:
            info.relro = "no"

        # Get canary
        returncode, stdout, _ = await self.execute(
            ["readelf", "-s", binary_path],
            timeout=10
        )

        info.canary = "__stack_chk_fail" in stdout

        # Get RPATH/RUNPATH
        returncode, stdout, _ = await self.execute(
            ["readelf", "-d", binary_path],
            timeout=10
        )

        for line in stdout.split("\n"):
            if "RPATH" in line:
                match = re.search(r"RPATH\\s+([\\w/]+)", line)
                if match:
                    info.rpath = match.group(1)
            if "RUNPATH" in line:
                match = re.search(r"RUNPATH\\s+([\\w/]+)", line)
                if match:
                    info.runpath = match.group(1)

        # Check if stripped
        info.stripped = "__bss_start" not in stdout and "__stop_" not in stdout

        # Check if static
        info.static = "ld-linux" not in stdout and ".so" not in stdout

        return info

    async def _check_macho(self, binary_path: str) -> BinaryInfo:
        """Check Mach-O binary security features."""
        info = BinaryInfo(path=binary_path)

        # Get file info
        returncode, stdout, _ = await self.execute(
            ["file", "-b", binary_path],
            timeout=10
        )
        info.file_type = stdout.strip()

        # Get hashes
        with open(binary_path, "rb") as f:
            data = f.read()
            info.md5 = hashlib.md5(data).hexdigest()
            info.sha256 = hashlib.sha256(data).hexdigest()
            info.size = len(data)

        return info


class ROPGadgetTool(BaseTool):
    """Find ROP gadgets in binaries."""

    name = "ropgadget"
    description = "Find ROP gadgets in binaries"

    async def run(
        self,
        binary_path: str,
        only_bad: bool = False,
        no_jump: bool = False,
    ) -> List[Dict[str, str]]:
        """Find ROP gadgets."""
        args = ["ROPgadget", "--binary", binary_path, "--json"]

        if only_bad:
            args.append("--badbytes")
        if no_jump:
            args.append("--nojmp")

        returncode, stdout, stderr = await self.execute(args, timeout=120)

        if returncode != 0:
            self.logger.warning(f"ROPgadget error: {stderr}")
            return []

        try:
            data = json.loads(stdout)
            gadgets = []

            for gadget in data.get("gadgets", []):
                gadgets.append({
                    "address": gadget.get("address", ""),
                    "gadget": gadget.get("gadget", ""),
                    "instructions": gadget.get("instructions", ""),
                    "vaddr": gadget.get("vaddr", ""),
                })

            return gadgets

        except json.JSONDecodeError:
            self.logger.warning("Failed to parse ROPgadget JSON output")
            return []


class OneGadgetTool(BaseTool):
    """Find one-gadget RCE in libc."""

    name = "one_gadget"
    description = "Find one-gadget RCE addresses in libc"

    async def run(
        self,
        libc_path: str,
        level: int = 1,
    ) -> List[Dict[str, Any]]:
        """Find one-gadget RCE addresses."""
        args = ["one_gadget", libc_path, "-l", str(level), "--raw"]

        returncode, stdout, stderr = await self.execute(args, timeout=60)

        if returncode != 0:
            self.logger.warning(f"one_gadget error: {stderr}")
            return []

        gadgets = []
        for line in stdout.strip().split("\\n"):
            if not line:
                continue

            parts = line.split()
            if len(parts) >= 2:
                gadget = {
                    "address": parts[0],
                    "constraints": " ".join(parts[1:])
                }
                gadgets.append(gadget)

        return gadgets


class StringsTool(BaseTool):
    """Extract strings from binaries."""

    name = "strings"
    description = "Extract strings from binary files"

    async def run(
        self,
        binary_path: str,
        min_length: int = 4,
        encoding: str = "S",
    ) -> List[StringEntry]:
        """Extract strings from binary."""
        args = [
            "strings",
            "-n", str(min_length),
            "-e", encoding,
            binary_path
        ]

        returncode, stdout, stderr = await self.execute(args, timeout=60)

        if returncode != 0:
            self.logger.warning(f"strings error: {stderr}")
            return []

        entries = []
        for line in stdout.strip().split("\\n"):
            if not line:
                continue

            entries.append(StringEntry(
                address="",
                value=line.strip(),
                length=len(line.strip()),
                is_unicode=(encoding == "L"),
            ))

        return entries


class ReadelfTool(BaseTool):
    """ELF binary analysis using readelf."""

    name = "readelf"
    description = "ELF binary analysis tool"

    async def run(
        self,
        binary_path: str,
        section: str = "all",
    ) -> Dict[str, Any]:
        """Analyze ELF binary."""
        args = ["readelf", f"-{section[0]}", binary_path]

        returncode, stdout, stderr = await self.execute(args, timeout=60)

        if returncode != 0:
            self.logger.warning(f"readelf error: {stderr}")
            return {}

        return {
            "section": section,
            "output": stdout,
            "errors": stderr,
        }

    async def get_imports(self, binary_path: str) -> List[str]:
        """Get imported functions."""
        args = ["readelf", "-d", binary_path]

        returncode, stdout, stderr = await self.execute(args, timeout=30)

        imports = []
        for line in stdout.split("\\n"):
            if "NEEDED" in line:
                match = re.search(r'NEEDED\\s+\\[(.+?)\\]', line)
                if match:
                    imports.append(match.group(1))

        return imports

    async def get_exports(self, binary_path: str) -> List[str]:
        """Get exported symbols."""
        args = ["readelf", "-s", binary_path]

        returncode, stdout, stderr = await self.execute(args, timeout=30)

        exports = []
        for line in stdout.split("\\n"):
            if "@@GLIBC" in line or "@@U" in line:
                parts = line.split()
                if len(parts) >= 8:
                    exports.append(parts[-1])

        return exports


class ObjdumpTool(BaseTool):
    """Objdump wrapper for disassembly."""

    name = "objdump"
    description = "Disassemble binary files"

    async def run(
        self,
        binary_path: str,
        architecture: Optional[str] = None,
        disassemble: bool = True,
    ) -> str:
        """Disassemble binary."""
        args = ["objdump"]

        if disassemble:
            args.append("-d")

        if architecture:
            args.extend(["-m", architecture])
        else:
            args.append("-m")
            args.append("auto")

        args.append(binary_path)

        returncode, stdout, stderr = await self.execute(args, timeout=120)

        if returncode != 0:
            self.logger.warning(f"objdump error: {stderr}")
            return ""

        return stdout
