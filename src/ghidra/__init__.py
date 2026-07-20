"""Ghidra integration module for BugBounty MCP."""

import json
import os
import re
import subprocess
import tempfile
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import get_settings
from ..models import BinaryInfo, Function, StringEntry
from ..utils import BaseTool


class GhidraTool(BaseTool):
    """Ghidra headless analysis integration."""

    name = "ghidra"
    description = "Binary analysis using Ghidra headless mode"

    def __init__(self):
        super().__init__()
        self.settings = get_settings().ghidra

    def _get_headless_path(self) -> str:
        """Get the Ghidra headless analyzer path."""
        if self.settings.headless_path:
            return str(self.settings.headless_path)

        # Default path for Ghidra installation
        ghidra_dir = self.settings.install_path
        if not ghidra_dir.exists():
            raise FileNotFoundError(
                f"Ghidra not found at {ghidra_dir}. "
                "Please install Ghidra or set GHIDRA_INSTALL_PATH."
            )

        return str(ghidra_dir / "support" / "analyzeHeadless")

    def _create_analysis_script(
        self,
        project_name: str,
        binary_path: str,
        analysis_type: str = "full"
    ) -> str:
        """Create a Ghidra analysis script."""
        script = r'''
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.util.task.*;
import ghidra.app.services.*;

public class AnalysisScript extends GhidraScript {
    private String outputFile = System.getProperty("output.file", "ghidra_output.json");

    @Override
    protected void run() throws Exception {
        StringBuilder json = new StringBuilder();
        json.append("{");

        // Binary info
        Program program = getCurrentProgram();
        json.append("\"binary_info\": {");
        json.append("\"name\": \"" + program.getName() + "\",");
        json.append("\"architecture\": \"" + program.getLanguage().getProcessor().toString() + "\",");
        json.append("\"endian\": \"" + (program.getLanguage().isBigEndian() ? "big" : "little") + "\",");
        json.append("\"imageBase\": \"" + Long.toHexString(program.getImageBase().getOffset()) + "\"");
        json.append("},");

        // Functions
        json.append("\"functions\": [");
        boolean first = true;
        FunctionIterator functions = program.getListing().getFunctions(true);
        while (functions.hasNext()) {
            Function func = functions.next();
            if (!first) json.append(",");
            first = false;
            json.append("{");
            json.append("\"name\": \"" + func.getName() + "\",");
            json.append("\"address\": \"" + func.getEntryPoint().toString() + "\",");
            json.append("\"signature\": \"" + func.getSignature().toString().replace("\"", "\\\"") + "\"");
            if (func.hasCustomVariableStorage()) {
                json.append(",\"variables\": [");
                boolean firstVar = true;
                for (Variable var : func.getAllVariables()) {
                    if (!firstVar) json.append(",");
                    firstVar = false;
                    json.append("\"" + var.getName() + "\"");
                }
                json.append("]");
            }
            json.append("}");
        }
        json.append("],");

        // Strings
        json.append("\"strings\": [");
        first = true;
        DataIterator dataIter = program.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue() && data.getValue().toString().length() > 4) {
                if (!first) json.append(",");
                first = false;
                String strVal = data.getValue().toString().replace("\\", "\\\\").replace("\"", "\\\"");
                json.append("{");
                json.append("\"address\": \"" + data.getAddress().toString() + "\",");
                json.append("\"value\": \"" + strVal + "\",");
                json.append("\"length\": " + strVal.length());
                json.append("}");
            }
        }
        json.append("]");

        json.append("}");

        // Write output
        java.io.FileWriter writer = new java.io.FileWriter(outputFile);
        writer.write(json.toString());
        writer.close();
    }
}
'''
        return script

    async def analyze(
        self,
        binary_path: str,
        project_name: Optional[str] = None,
        analysis_type: str = "full"
    ) -> Dict[str, Any]:
        """Analyze a binary file using Ghidra headless."""
        if not Path(binary_path).exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        headless = self._get_headless_path()

        # Create temporary project directory
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir)
            script_file = project_dir / "AnalysisScript.java"
            output_file = project_dir / "ghidra_output.json"

            # Write analysis script
            script_content = self._create_analysis_script(
                project_name or "analysis",
                binary_path,
                analysis_type
            )
            script_file.write_text(script_content)

            if project_name is None:
                project_name = Path(binary_path).stem

            cmd = [
                headless,
                str(project_dir),
                project_name,
                "-import", binary_path,
                "-scriptPath", str(project_dir),
                "-postScript", "AnalysisScript.java",
                "-deleteProject",
                f"-Doutput.file={output_file}",
            ]

            proc = await self._run_ghidra(cmd, cwd=project_dir)

            if proc.returncode != 0:
                stderr = proc.stderr.decode() if proc.stderr else ""
                raise Exception(f"Ghidra analysis failed: {stderr}")

            if output_file.exists():
                return json.loads(output_file.read_text())

        return {}

    async def decompile_function(
        self,
        binary_path: str,
        function_name: str
    ) -> str:
        """Decompile a specific function."""
        output = await self.analyze(binary_path)

        for func in output.get("functions", []):
            if func.get("name") == function_name:
                return func.get("decompiled", f"Function: {function_name}")

        return f"Function {function_name} not found"

    async def list_functions(self, binary_path: str) -> List[Function]:
        """List all functions in a binary."""
        output = await self.analyze(binary_path)

        functions = []
        for func_data in output.get("functions", []):
            functions.append(Function(
                name=func_data.get("name", ""),
                address=func_data.get("address", ""),
                signature=func_data.get("signature", ""),
            ))

        return functions

    async def get_strings(self, binary_path: str) -> List[StringEntry]:
        """Extract strings from a binary."""
        output = await self.analyze(binary_path)

        strings = []
        for str_data in output.get("strings", []):
            strings.append(StringEntry(
                address=str_data.get("address", ""),
                value=str_data.get("value", ""),
                length=str_data.get("length", 0),
            ))

        return strings

    async def get_binary_info(self, binary_path: str) -> BinaryInfo:
        """Get basic binary information."""
        output = await self.analyze(binary_path)

        info = output.get("binary_info", {})

        # Additional analysis with readelf
        readelf_output = ""
        try:
            proc = await self._run_subprocess([
                "readelf", "-h", binary_path
            ])
            readelf_output = proc.stdout.decode()
        except Exception:
            pass

        # Parse readelf output
        arch = info.get("architecture", "")
        stripped = "no"

        for line in readelf_output.split("\n"):
            if "Machine:" in line:
                arch = line.split("Machine:")[1].strip()
            elif "Flags:" in line:
                if "0x" in line:
                    try:
                        flags = int(line.split("0x")[1].split()[0], 16)
                        if flags & 0x10:
                            stripped = "yes"
                    except:
                        pass

        return BinaryInfo(
            path=binary_path,
            architecture=arch,
            linker=info.get("linker", ""),
            stripped=stripped == "yes",
            pie=info.get("pie", False),
        )

    async def _run_ghidra(self, cmd: List[str], cwd: Path = None) -> subprocess.CompletedProcess:
        """Run Ghidra headless analyzer."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout, stderr = await proc.communicate()

        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)

    async def _run_subprocess(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run a subprocess command."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


# Need to import asyncio
import asyncio
