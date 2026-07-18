"""Mobile security analysis module for BugBounty MCP."""

import asyncio
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Vulnerability, Severity, VulnerabilityType
from ..utils import BaseTool


class JadxTool(BaseTool):
    """Android APK decompiler using JADX."""

    name = "jadx"
    description = "Decompile Android APK files"

    async def run(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        deobfuscate: bool = True,
    ) -> str:
        """Decompile an Android APK file."""
        if not Path(apk_path).exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        if output_dir is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                return await self._decompile(apk_path, tmpdir, deobfuscate)
        else:
            return await self._decompile(apk_path, output_dir, deobfuscate)

    async def _decompile(
        self,
        apk_path: str,
        output_dir: str,
        deobfuscate: bool
    ) -> str:
        """Internal decompilation method."""
        args = [
            "jadx",
            "-d", output_dir,
            "--no-res",
        ]

        if deobfuscate:
            args.append("-d")  # decompile

        args.append(apk_path)

        returncode, stdout, stderr = await self.execute(args, timeout=300)

        if returncode != 0:
            self.logger.warning(f"jadx error: {stderr}")
            return ""

        return output_dir


class ApktoolTool(BaseTool):
    """Android APK reverse engineering tool."""

    name = "apktool"
    description = "Reverse engineer Android APK files"

    async def run(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        decode_resources: bool = True,
    ) -> str:
        """Decode an Android APK file."""
        if not Path(apk_path).exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        if output_dir is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                return await self._decode(apk_path, tmpdir, decode_resources)
        else:
            return await self._decode(apk_path, output_dir, decode_resources)

    async def _decode(
        self,
        apk_path: str,
        output_dir: str,
        decode_resources: bool
    ) -> str:
        """Internal decode method."""
        args = ["apktool", "d", "-f"]

        if decode_resources:
            args.append("-r")  # Skip resource decoding

        args.extend(["-o", output_dir, apk_path])

        returncode, stdout, stderr = await self.execute(args, timeout=120)

        if returncode != 0:
            self.logger.warning(f"apktool error: {stderr}")
            return ""

        return output_dir


class ApkAnalyzerTool(BaseTool):
    """Static APK analyzer."""

    name = "apkanalyzer"
    description = "Analyze Android APK for security issues"

    async def run(self, apk_path: str) -> List[Vulnerability]:
        """Analyze an APK for security issues."""
        vulnerabilities = []

        if not Path(apk_path).exists():
            return vulnerabilities

        # Extract APK
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)

            # Unzip APK
            with zipfile.ZipFile(apk_path, "r") as zip_ref:
                zip_ref.extractall(tmpdir)

            # Check AndroidManifest.xml
            manifest_path = tmpdir / "AndroidManifest.xml"
            if manifest_path.exists():
                vulnerabilities.extend(await self._analyze_manifest(manifest_path))

            # Check for backup enabled
            backup_path = tmpdir / "META-INF"
            if backup_path.exists():
                vulnerabilities.extend(await self._check_backup(backup_path, apk_path))

            # Check lib directory
            lib_path = tmpdir / "lib"
            if lib_path.exists():
                vulnerabilities.extend(await self._check_native_libs(lib_path, apk_path))

            # Check assets
            assets_path = tmpdir / "assets"
            if assets_path.exists():
                vulnerabilities.extend(await self._check_assets(assets_path, apk_path))

            # Check for hardcoded secrets
            vulnerabilities.extend(await self._check_secrets(tmpdir, apk_path))

        return vulnerabilities

    async def _analyze_manifest(
        self,
        manifest_path: Path
    ) -> List[Vulnerability]:
        """Analyze AndroidManifest.xml."""
        vulnerabilities = []
        apk_path = str(manifest_path.parent)

        try:
            content = manifest_path.read_text()

            # Check for debuggable
            if "android:debuggable" in content:
                if "true" in content:
                    vulnerabilities.append(Vulnerability(
                        name="Debuggable App Enabled",
                        type=VulnerabilityType.OTHER,
                        severity=Severity.HIGH,
                        target=apk_path,
                        description="Android application has debuggable flag enabled in manifest",
                        remediation="Set android:debuggable to false in production builds",
                    ))

            # Check for allowBackup
            if "android:allowBackup" in content:
                if "true" in content:
                    vulnerabilities.append(Vulnerability(
                        name="Data Backup Enabled",
                        type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        severity=Severity.INFO,
                        target=apk_path,
                        description="Android application allows backup of application data",
                        remediation="Set android:allowBackup to false to prevent data leakage",
                    ))

            # Check for cleartext traffic
            if "android:usesCleartextTraffic" in content:
                if "true" in content:
                    vulnerabilities.append(Vulnerability(
                        name="Cleartext Traffic Allowed",
                        type=VulnerabilityType.OTHER,
                        severity=Severity.MEDIUM,
                        target=apk_path,
                        description="Application allows cleartext (HTTP) traffic",
                        remediation="Use HTTPS only and set android:usesCleartextTraffic to false",
                    ))

            # Check for exported components
            exported_patterns = [
                'android:exported="true"',
                "android:exported='true'",
            ]
            for pattern in exported_patterns:
                if pattern in content:
                    # Count exported activities/services/receivers
                    count = content.count(pattern)
                    vulnerabilities.append(Vulnerability(
                        name=f"Exported Components ({count})",
                        type=VulnerabilityType.AUTHORIZATION,
                        severity=Severity.MEDIUM,
                        target=apk_path,
                        description=f"Found {count} exported components in AndroidManifest.xml",
                        remediation="Review and protect exported components with proper permissions",
                    ))
                    break

        except Exception as e:
            self.logger.debug(f"Manifest analysis error: {e}")

        return vulnerabilities

    async def _check_backup(
        self,
        backup_path: Path,
        apk_path: str
    ) -> List[Vulnerability]:
        """Check for backup-related issues."""
        vulnerabilities = []

        # Check for Android backup agent
        for manifest_xml in backup_path.rglob("*.xml"):
            try:
                content = manifest_xml.read_text()
                if "android:backupAgent" in content:
                    vulnerabilities.append(Vulnerability(
                        name="Custom Backup Agent",
                        type=VulnerabilityType.INFORMATION_DISCLOSURE,
                        severity=Severity.INFO,
                        target=apk_path,
                        description="Application uses a custom backup agent",
                    ))
            except Exception:
                pass

        return vulnerabilities

    async def _check_native_libs(
        self,
        lib_path: Path,
        apk_path: str
    ) -> List[Vulnerability]:
        """Check native libraries."""
        vulnerabilities = []

        for arch_dir in lib_path.iterdir():
            if arch_dir.is_dir():
                for lib_file in arch_dir.iterdir():
                    if lib_file.suffix in [".so"]:
                        # Check if library is stripped
                        args = ["file", str(lib_file)]
                        returncode, stdout, _ = await self.execute(args, timeout=10)

                        if "not stripped" in stdout:
                            vulnerabilities.append(Vulnerability(
                                name="Native Library Not Stripped",
                                type=VulnerabilityType.INFORMATION_DISCLOSURE,
                                severity=Severity.INFO,
                                target=str(lib_file),
                                description=f"Native library {lib_file.name} is not stripped, exposing symbol information",
                            ))
                        break

        return vulnerabilities

    async def _check_assets(
        self,
        assets_path: Path,
        apk_path: str
    ) -> List[Vulnerability]:
        """Check assets directory for sensitive files."""
        vulnerabilities = []

        sensitive_files = ["config.json", "credentials.json", "secrets.json"]

        for sf in sensitive_files:
            for f in assets_path.rglob(sf):
                vulnerabilities.append(Vulnerability(
                    name=f"Sensitive File in Assets: {sf}",
                    type=VulnerabilityType.INFORMATION_DISCLOSURE,
                    severity=Severity.HIGH,
                    target=apk_path,
                    description=f"Found potentially sensitive file '{sf}' in assets directory",
                    remediation="Remove sensitive files from APK assets before release",
                ))

        return vulnerabilities

    async def _check_secrets(
        self,
        apk_dir: Path,
        apk_path: str
    ) -> List[Vulnerability]:
        """Check for hardcoded secrets."""
        vulnerabilities = []

        patterns = [
            (r"api[_-]?key[\"']?\\s*[:=]\\s*[\"'][A-Za-z0-9_-]{20,}", "API Key"),
            (r"password[\"']?\\s*[:=]\\s*[\"'][^\"']{8,}", "Hardcoded Password"),
            (r"secret[\"']?\\s*[:=]\\s*[\"'][^\"']{16,}", "Secret Key"),
            (r"token[\"']?\\s*[:=]\\s*[\"'][A-Za-z0-9_-]{20,}", "Auth Token"),
        ]

        for smali_file in apk_dir.rglob("*.smali"):
            try:
                content = smali_file.read_text(errors="ignore")

                for pattern, secret_type in patterns:
                    import re
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append(Vulnerability(
                            name=f"Potential Hardcoded Secret: {secret_type}",
                            type=VulnerabilityType.INFORMATION_DISCLOSURE,
                            severity=Severity.HIGH,
                            target=str(smali_file),
                            description=f"Found potential hardcoded {secret_type} in smali code",
                            remediation=f"Remove hardcoded {secret_type} from source code",
                        ))
            except Exception:
                pass

        return vulnerabilities


class ClassDumpTool(BaseTool):
    """Dump Objective-C class information from iOS binaries."""

    name = "classdump"
    description = "Dump Objective-C classes from iOS binaries"

    async def run(
        self,
        binary_path: str,
        output_dir: Optional[str] = None,
    ) -> List[str]:
        """Dump Objective-C classes from an iOS binary."""
        if output_dir is None:
            with tempfile.TemporaryDirectory() as tmpdir:
                return await self._dump(binary_path, tmpdir)
        else:
            return await self._dump(binary_path, output_dir)

    async def _dump(
        self,
        binary_path: str,
        output_dir: str
    ) -> List[str]:
        """Internal dump method."""
        args = ["class-dump-z", "-H", "-o", output_dir, binary_path]

        returncode, stdout, stderr = await self.execute(args, timeout=120)

        if returncode != 0:
            self.logger.warning(f"class-dump error: {stderr}")
            return []

        # Return list of generated header files
        headers = []
        for header in Path(output_dir).glob("*.h"):
            headers.append(str(header))

        return headers


class FridaTool(BaseTool):
    """Dynamic instrumentation using Frida."""

    name = "frida"
    description = "Dynamic instrumentation toolkit"

    async def run_script(
        self,
        target: str,
        script: str,
        spawn: bool = False,
    ) -> str:
        """Run a Frida script against a target."""
        args = ["frida", "-l", "-"]

        if spawn:
            args.append("-f")
        else:
            args.append("-n")

        args.append(target)

        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await proc.communicate(input=script.encode())

        return stdout.decode() + stderr.decode()

    async def list_modules(self, target: str) -> List[str]:
        """List loaded modules in a process."""
        script = """
        Process.enumerateModules().forEach(function(module) {
            console.log(module.name);
        });
        """

        output = await self.run_script(target, script)
        return [line.strip() for line in output.split("\n") if line.strip()]

    async def list_imports(self, target: str, module: str) -> List[str]:
        """List imported functions in a module."""
        script = f"""
        var mod = Process.findModuleByName("{module}");
        if (mod) {{
            mod.enumerateImports().forEach(function(imp) {{
                console.log(imp.name);
            }});
        }}
        """

        output = await self.run_script(target, script)
        return [line.strip() for line in output.split("\n") if line.strip()]
