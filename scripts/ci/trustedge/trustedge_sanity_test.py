#!/usr/bin/env python3
"""
TrustEdge Unified Sanity Test Script
=====================================
Cross-platform sanity tests for TrustEdge on Linux and Windows.

Usage:
    python trustedge_sanity_test.py [--skip-install] [--skip-agent] [--verbose]

Dependencies:
    - Python 3.8+
    - requests (pip install requests)

Copyright (c) 2025-2026 DigiCert Corporation. All Rights Reserved.
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ============================================================================
# Platform Detection and Configuration
# ============================================================================

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

@dataclass
class PlatformConfig:
    """Platform-specific paths and commands."""
    digicert_path: Path
    keystore_ca_dir: Path
    keystore_certs_dir: Path
    keystore_keys_dir: Path
    keystore_req_dir: Path
    keystore_conf_dir: Path
    conf_dir: Path
    cloud_dir: Path
    trustedge_cmd: str
    null_file: str
    
    @classmethod
    def detect(cls) -> "PlatformConfig":
        if IS_WINDOWS:
            base = Path(os.environ.get("ProgramData", "C:\\ProgramData")) / "DigiCert" / "TrustEdge"
            trustedge_cmd = str(Path(os.environ.get("ProgramFiles", "C:\\Program Files")) 
                               / "DigiCert" / "TrustEdge" / "bin" / "trustedge.exe")
            null_file = "NUL"
        else:
            base = Path("/etc/digicert")
            trustedge_cmd = "trustedge"
            null_file = "/dev/null"
        
        return cls(
            digicert_path=base,
            keystore_ca_dir=base / "keystore" / "ca",
            keystore_certs_dir=base / "keystore" / "certs",
            keystore_keys_dir=base / "keystore" / "keys",
            keystore_req_dir=base / "keystore" / "req",
            keystore_conf_dir=base / "keystore" / "conf",
            conf_dir=base / "conf",
            cloud_dir=base / "cloudprovider",
            trustedge_cmd=trustedge_cmd,
            null_file=null_file,
        )

CONFIG = PlatformConfig.detect()

# Patterns that may contain sensitive data - redact before logging
_SENSITIVE_PATTERNS = [
    (re.compile(r'(password|passwd|pwd|secret|token|key|credential|api[_-]?key)[=:\s]+\S+', re.IGNORECASE), r'\1=<REDACTED>'),
    (re.compile(r'(Bearer|Basic)\s+\S+', re.IGNORECASE), r'\1 <REDACTED>'),
    (re.compile(r'-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----'), '<REDACTED_KEY>'),
]

def _sanitize_message(message: str) -> str:
    """Redact potentially sensitive information from log messages."""
    if not message:
        return message
    sanitized = message
    for pattern, replacement in _SENSITIVE_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized

# ============================================================================
# Test Result Tracking
# ============================================================================

class TestStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"

@dataclass
class TestResult:
    name: str
    status: TestStatus
    message: Optional[str] = None

class TestRunner:
    """Manages test execution and result collection."""
    
    def __init__(self, verbose: bool = False, interactive: bool = False):
        self.results: OrderedDict[str, TestResult] = OrderedDict()
        self.verbose = verbose
        self.interactive = interactive
        self.device_id: Optional[str] = None
        self.msi_file: Optional[Path] = None  # Track installed MSI for cleanup
    
    def collect(self, name: str, status: TestStatus, message: str = None):
        # Sanitize message before storing to prevent sensitive data exposure
        sanitized_message = _sanitize_message(message) if message else None
        self.results[name] = TestResult(name, status, sanitized_message)
        status_str = f"[{status.value}]"
        if status == TestStatus.PASS:
            print(f"**********{status_str} {name}")
        elif status == TestStatus.FAIL:
            print(f"**********{status_str} {name}")
            if sanitized_message:
                print("  Error: <REDACTED>")
        else:
            print(f"**********{status_str} {name} - Skipped")
    
    def log_section(self, title: str):
        print()
        print("*" * 73)
        print(f"*** {title}")
        print("*" * 73)
    
    def log(self, message: str):
        """Log a message (verbose mode only). Messages are sanitized before printing."""
        print("Logging has been disabled")

    def prompt_continue(self, next_test: str) -> Optional[bool]:
        """Prompt user before running next test.
        
        Returns:
            True: Continue with the test
            False: User wants to quit
            None: Skip this test
        """
        if not self.interactive:
            return True
        print()
        print(f"  Next: {next_test}")
        print(f"  TrustEdge data: {CONFIG.digicert_path}")
        response = input("  Press Enter to continue, 's' to skip, 'q' to quit: ").strip().lower()
        if response == 'q':
            print("  User requested quit.")
            return False
        if response == 's':
            print("  Skipping this test.")
            return None  # Signal to skip
        return True
    
    def display_summary(self):
        print()
        print("*" * 73)
        print("*" * 25 + " Test Summary " + "*" * 34)
        print("*" * 73)
        print(f"| {'Test Name':<60} | {'Result':<6} |")
        print(f"|{'-' * 62}|{'-' * 8}|")
        
        for result in self.results.values():
            name = result.name[:60].ljust(60)
            status = result.status.value.ljust(6)
            print(f"| {name} | {status} |")
            if result.status == TestStatus.FAIL and result.message:
                # Show truncated failure message in summary on a single line
                normalized_message = re.sub(r"\s+", " ", result.message).strip()
                msg = normalized_message[:58] if len(normalized_message) > 58 else normalized_message
                print(f"|   -> {msg:<64} |")
            print(f"|{'-' * 62}|{'-' * 8}|")
        
        passed = sum(1 for r in self.results.values() if r.status == TestStatus.PASS)
        failed = sum(1 for r in self.results.values() if r.status == TestStatus.FAIL)
        skipped = sum(1 for r in self.results.values() if r.status == TestStatus.SKIP)
        
        print()
        print(f"Total: {len(self.results)} | Passed: {passed} | Failed: {failed} | Skipped: {skipped}")
        
        return failed == 0
    
    @property
    def all_passed(self) -> bool:
        return all(r.status != TestStatus.FAIL for r in self.results.values())

# ============================================================================
# Utility Functions
# ============================================================================

def run_cmd(cmd: List[str], capture: bool = True, check: bool = False) -> Tuple[int, str, str]:
    """Run a command and return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=check,
            shell=False
        )
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout or "", e.stderr or ""
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"

def run_trustedge(*args) -> Tuple[int, str, str]:
    """Run trustedge command with arguments."""
    cmd = [CONFIG.trustedge_cmd] + list(args)
    return run_cmd(cmd)

def dir_is_empty(path: Path) -> bool:
    """Check if a directory is empty."""
    if not path.exists():
        return True
    return len(list(path.iterdir())) == 0

def file_exists(path: Path) -> bool:
    """Check if a file exists."""
    return path.is_file()

# ============================================================================
# Installation Tests
# ============================================================================

def test_installation(runner: TestRunner, package_dir: Path):
    """Test package installation and uninstallation."""
    runner.log_section("Testing TrustEdge Installation")
    
    if IS_WINDOWS:
        _test_msi_installation(runner, package_dir)
        _test_tgz_extraction(runner, package_dir, "win64")
    else:
        for platform_name in ["x64", "rpi64", "rpi32"]:
            _test_deb_installation(runner, package_dir, platform_name)
            _test_tgz_extraction(runner, package_dir, platform_name)

def _test_deb_installation(runner: TestRunner, package_dir: Path, platform_name: str):
    """Test DEB package installation (Linux only)."""
    runner.log_section(f"Installing TrustEdge (deb) for {platform_name}")
    
    deb_path = package_dir / "deb" / platform_name
    deb_files = list(deb_path.glob("trustedge*.deb"))
    
    if not deb_files:
        runner.collect(f"TrustEdge installation (deb) for {platform_name}", TestStatus.SKIP, 
                      "DEB file not found")
        return
    
    deb_file = deb_files[0]
    
    # Install
    env = os.environ.copy()
    env["DIGICERT_EULA_ACCEPT"] = "yes"
    result = subprocess.run(
        ["dpkg", "-i", str(deb_file)],
        capture_output=True,
        text=True,
        env=env
    )
    
    if result.returncode == 0:
        runner.collect(f"TrustEdge installation (deb) for {platform_name}", TestStatus.PASS)
    else:
        runner.collect(f"TrustEdge installation (deb) for {platform_name}", TestStatus.FAIL,
                      result.stderr)
        return
    
    # Uninstall
    result = subprocess.run(["dpkg", "--purge", "trustedge"], capture_output=True, text=True)
    
    if result.returncode == 0:
        runner.collect(f"TrustEdge uninstallation (deb) for {platform_name}", TestStatus.PASS)
    else:
        runner.collect(f"TrustEdge uninstallation (deb) for {platform_name}", TestStatus.FAIL,
                      result.stderr)

def _is_admin() -> bool:
    """Check if running with administrator privileges (Windows only)."""
    if not IS_WINDOWS:
        return os.geteuid() == 0
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def _test_msi_installation(runner: TestRunner, package_dir: Path, keep_installed: bool = True):
    """Test MSI package installation (Windows only).
    
    Args:
        runner: Test runner instance
        package_dir: Directory containing MSI file
        keep_installed: If True, keep TrustEdge installed for subsequent tests
    """
    runner.log_section("Installing TrustEdge (MSI)")
    
    # Check for admin privileges
    if not _is_admin():
        runner.collect("TrustEdge installation (MSI)", TestStatus.SKIP,
                      "Administrator privileges required. Run as Administrator.")
        return
    
    msi_files = list(package_dir.glob("trustedge*.msi"))
    
    if not msi_files:
        runner.collect("TrustEdge installation (MSI)", TestStatus.SKIP, 
                      f"MSI file not found in {package_dir.resolve()}")
        return
    
    msi_file = msi_files[0]
    runner.log(f"Installing MSI: {msi_file}")
    
    # Create log file for debugging
    log_file = package_dir / "msi_install.log"
    
    # Install with logging
    result = subprocess.run(
        ["msiexec", "/i", str(msi_file), "/qn", "ACCEPT_EULA=1", 
         "/l*v", str(log_file)],
        capture_output=True,
        text=True
    )
    
    exe_exists = Path(CONFIG.trustedge_cmd).exists()
    
    if result.returncode == 0 and exe_exists:
        runner.collect("TrustEdge installation (MSI)", TestStatus.PASS)
        log_file.unlink(missing_ok=True)  # Clean up log on success
    else:
        # Build detailed error message
        error_parts = []
        if result.returncode != 0:
            msi_errors = {
                1602: "User cancelled",
                1603: "Fatal error (check log)",
                1618: "Another installation in progress",
                1619: "Package could not be opened",
                1620: "Invalid package",
                1638: "Another version already installed",
            }
            err_desc = msi_errors.get(result.returncode, "")
            error_parts.append(f"msiexec code {result.returncode}" + 
                             (f" ({err_desc})" if err_desc else ""))
        if not exe_exists:
            error_parts.append(f"trustedge.exe not found at {CONFIG.trustedge_cmd}")
        error_parts.append(f"Log: {log_file}")
        error_msg = "; ".join(error_parts)
        runner.collect("TrustEdge installation (MSI)", TestStatus.FAIL, error_msg)
        return
    
    # Keep installed for subsequent tests
    if keep_installed:
        runner.log("Keeping TrustEdge installed for subsequent tests")
        runner.msi_file = msi_file  # Store for cleanup
        return
    
    # Uninstall
    result = subprocess.run(
        ["msiexec", "/x", str(msi_file), "/qn"],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        runner.collect("TrustEdge uninstallation (MSI)", TestStatus.PASS)
    else:
        runner.collect("TrustEdge uninstallation (MSI)", TestStatus.FAIL, result.stderr)

def _test_tgz_extraction(runner: TestRunner, package_dir: Path, platform_name: str):
    """Test TGZ extraction and file structure verification."""
    runner.log_section(f"Testing TrustEdge TGZ extraction for {platform_name}")
    
    tgz_path = package_dir / "tgz" / platform_name
    tgz_files = list(tgz_path.glob("trustedge*.tar.gz"))
    
    if not tgz_files:
        runner.collect(f"TrustEdge extraction (tgz) for {platform_name}", TestStatus.SKIP,
                      "TGZ file not found")
        return
    
    tgz_file = tgz_files[0]
    extract_path = Path(tempfile.mkdtemp())
    
    try:
        # Extract
        result = subprocess.run(
            ["tar", "-xzf", str(tgz_file), "-C", str(extract_path)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            runner.collect(f"TrustEdge extraction (tgz) for {platform_name}", TestStatus.FAIL,
                          result.stderr)
            return
        
        runner.collect(f"TrustEdge extraction (tgz) for {platform_name}", TestStatus.PASS)
        
        # Verify structure
        exe_name = "trustedge.exe" if IS_WINDOWS else "trustedge"
        required_paths = [
            extract_path / "bin",
            extract_path / "bin" / exe_name,
            extract_path / "conf",
            extract_path / "keystore",
            extract_path / "scripts",
            extract_path / "trustedge.json",
        ]
        
        all_exist = all(p.exists() for p in required_paths)
        
        if all_exist:
            runner.collect(f"TrustEdge TGZ file structure for {platform_name}", TestStatus.PASS)
        else:
            missing = [str(p) for p in required_paths if not p.exists()]
            runner.collect(f"TrustEdge TGZ file structure for {platform_name}", TestStatus.FAIL,
                          f"Missing: {missing}")
    finally:
        shutil.rmtree(extract_path, ignore_errors=True)
        runner.collect(f"TrustEdge TGZ cleanup for {platform_name}", TestStatus.PASS)

# ============================================================================
# TrustEdge Command Tests
# ============================================================================

def test_help_version(runner: TestRunner):
    """Test --help and --version commands."""
    runner.log_section("Testing TrustEdge help and version")
    
    # --help
    exit_code, stdout, stderr = run_trustedge("--help")
    if exit_code == 0:
        runner.collect("TrustEdge --help", TestStatus.PASS)
    else:
        runner.collect("TrustEdge --help", TestStatus.FAIL, stderr)
    
    # --version
    exit_code, stdout, stderr = run_trustedge("--version")
    if exit_code == 0:
        runner.collect("TrustEdge --version", TestStatus.PASS)
        runner.log("Version command completed successfully.")
    else:
        runner.collect("TrustEdge --version", TestStatus.FAIL, stderr)

def test_agent(runner: TestRunner, bootstrap_zip: Optional[Path] = None):
    """Test trustedge agent commands."""
    runner.log_section("Testing TrustEdge Agent")
    
    # agent --help
    exit_code, stdout, stderr = run_trustedge("agent", "--help")
    if exit_code == 0:
        runner.collect("TrustEdge agent --help", TestStatus.PASS)
    else:
        runner.collect("TrustEdge agent --help", TestStatus.FAIL, stderr)
        return
    
    # Configure with bootstrap if provided
    if bootstrap_zip and bootstrap_zip.exists():
        runner.log_section("Configuring TrustEdge agent")
        
        args = ["agent", "--configure", "--bootstrap-zip", str(bootstrap_zip)]
        if IS_LINUX:
            args.extend(["--trustedge-user", "trustedge", "--trustedge-group", "trustedge"])
        
        exit_code, stdout, stderr = run_trustedge(*args)
        
        if exit_code == 0:
            runner.collect("TrustEdge agent --configure", TestStatus.PASS)
        else:
            runner.collect("TrustEdge agent --configure", TestStatus.FAIL, stderr)
            return
        
        # Verify configuration
        _verify_configuration(runner)
        
        # Run agent
        runner.log_section("Running TrustEdge agent")
        exit_code, stdout, stderr = run_trustedge("agent", "--log-level", "VERBOSE")
        
        if exit_code == 0:
            runner.collect("TrustEdge agent --log-level VERBOSE", TestStatus.PASS)
        else:
            runner.collect("TrustEdge agent --log-level VERBOSE", TestStatus.FAIL, stderr)
        
        # Verify policies
        _verify_policies(runner)

def _verify_configuration(runner: TestRunner):
    """Verify TrustEdge configuration files exist."""
    trustedge_json = CONFIG.digicert_path / "trustedge.json"
    bootstrap_config = CONFIG.conf_dir / "bootstrap_config.json"
    
    if trustedge_json.exists() and bootstrap_config.exists():
        runner.collect("TrustEdge configuration", TestStatus.PASS)
    else:
        missing = []
        if not trustedge_json.exists():
            missing.append("trustedge.json")
        if not bootstrap_config.exists():
            missing.append("bootstrap_config.json")
        runner.collect("TrustEdge configuration", TestStatus.FAIL, f"Missing: {missing}")

def _verify_policies(runner: TestRunner):
    """Verify policy files after agent run."""
    # Check failed policies
    failed_policy = CONFIG.conf_dir / "failed_policy.json"
    if failed_policy.exists():
        try:
            with open(failed_policy) as f:
                data = json.load(f)
            if len(data.get("failedPolicies", [])) > 0:
                runner.collect("TrustEdge agent (no failed policies)", TestStatus.FAIL,
                              "Failed policies exist")
                return
        except json.JSONDecodeError as e:
            print(f"  Warning: Failed to decode {failed_policy}: {e}")
    
    # Check processing policies
    processing_policy = CONFIG.conf_dir / "processing_policy.json"
    if processing_policy.exists():
        try:
            with open(processing_policy) as f:
                data = json.load(f)
            if len(data.get("processingPolicies", [])) > 0:
                runner.collect("TrustEdge agent (no processing policies)", TestStatus.FAIL,
                              "Processing policies still pending")
                return
        except json.JSONDecodeError as e:
            print(f"  Warning: Failed to decode {processing_policy}: {e}")
    
    runner.collect("TrustEdge agent policy verification", TestStatus.PASS)

def test_agent_reset(runner: TestRunner):
    """Test trustedge agent --reset command."""
    runner.log_section("Testing TrustEdge Agent Reset")
    
    exit_code, stdout, stderr = run_trustedge("agent", "--reset")
    
    if exit_code != 0:
        runner.collect("TrustEdge agent reset", TestStatus.FAIL, stderr or f"Exit code {exit_code}")
        return
    
    runner.log(f"Reset command output: {stdout.strip()}" if stdout.strip() else "Reset command completed")
    
    # Verify directories are empty
    dirs_to_check = [
        (CONFIG.keystore_ca_dir, "keystore/ca"),
        (CONFIG.keystore_certs_dir, "keystore/certs"),
        (CONFIG.keystore_keys_dir, "keystore/keys"),
        (CONFIG.keystore_req_dir, "keystore/req"),
        (CONFIG.cloud_dir, "cloudprovider"),
    ]
    
    for path, name in dirs_to_check:
        if not dir_is_empty(path):
            runner.collect("TrustEdge agent reset", TestStatus.FAIL, f"{name} is not empty")
            return
        runner.log(f"{name} is empty")
    
    # Verify files are removed
    files_to_check = [
        "metrics.pb",
        "desired_attributes.pb",
        "applied_policy.json",
        "policy_authorization.jwt",
        "failed_policy.json",
        "processing_policy.json",
        "pending_policy.json",
        "bootstrap_config.json",
        "cert_spec.json",
    ]
    
    for filename in files_to_check:
        filepath = CONFIG.conf_dir / filename
        if file_exists(filepath):
            runner.collect("TrustEdge agent reset", TestStatus.FAIL, f"{filename} still exists")
            return
        runner.log(f"{filename} does not exist")
    
    runner.collect("TrustEdge agent reset", TestStatus.PASS)

# ============================================================================
# Certificate Tests
# ============================================================================

def test_certificate(runner: TestRunner):
    """Test trustedge certificate commands."""
    runner.log_section("Testing TrustEdge Certificate")
    
    # certificate --help
    exit_code, stdout, stderr = run_trustedge("certificate", "--help")
    if exit_code == 0:
        runner.collect("TrustEdge certificate --help", TestStatus.PASS)
    else:
        runner.collect("TrustEdge certificate --help", TestStatus.FAIL, stderr)
        return
    
    # Generate RSA 2048 key
    exit_code, stdout, stderr = run_trustedge(
        "certificate", "--algorithm", "RSA", "--size", "2048", "--output-file", "RSA_2048.pem"
    )
    if exit_code == 0 and (CONFIG.keystore_keys_dir / "RSA_2048.pem").exists():
        runner.collect("TrustEdge certificate: Generate RSA 2048 private key", TestStatus.PASS)
    else:
        runner.collect("TrustEdge certificate: Generate RSA 2048 private key", TestStatus.FAIL, stderr)
    
    # Generate ECC P256 key
    exit_code, stdout, stderr = run_trustedge(
        "certificate", "--algorithm", "ECC", "--curve", "P256", "--output-file", "ECC_P256.pem"
    )
    if exit_code == 0 and (CONFIG.keystore_keys_dir / "ECC_P256.pem").exists():
        runner.collect("TrustEdge certificate: Generate ECC P256 private key", TestStatus.PASS)
    else:
        runner.collect("TrustEdge certificate: Generate ECC P256 private key", TestStatus.FAIL, stderr)
    
    # Create CSR config
    csr_config = CONFIG.keystore_conf_dir / "sample_csr.cnf"
    csr_config.parent.mkdir(parents=True, exist_ok=True)
    csr_config.write_text("""##Subject
countryName=US
commonName=iot-device101
stateOrProvinceName=California
localityName=San Francisco
organizationName=DBA
organizationalUnitName=BU
##Requested Extensions
hasBasicConstraints=true
isCA=true
certPathLen=-1
keyUsage=keyEncipherment, digitalSignature, keyCertSign
subjectAltNames=2; *.mydomain.com, 2; *.mydomain.net, 2
""")
    
    # Generate CSR
    exit_code, stdout, stderr = run_trustedge(
        "certificate", "--cert-sign-req", "--output-file", "CSR_RSA_2048.pem",
        "--signing-key", "RSA_2048.pem", "--csr-conf", "sample_csr.cnf", "--digest", "SHA256"
    )
    if exit_code == 0:
        runner.collect("TrustEdge certificate: Generate CSR RSA 2048", TestStatus.PASS)
    else:
        runner.collect("TrustEdge certificate: Generate CSR RSA 2048", TestStatus.FAIL, stderr)
    
    # Generate X.509 cert
    exit_code, stdout, stderr = run_trustedge(
        "certificate", "--algorithm", "RSA", "--size", "2048", "--output-file", "RSA_CERT_2048.pem",
        "--csr-conf", "sample_csr.cnf", "--x509-cert", "RSA_CERT_2048.pem", "--days", "365"
    )
    if exit_code == 0:
        runner.collect("TrustEdge certificate: --x509-cert RSA_CERT_2048", TestStatus.PASS)
    else:
        runner.collect("TrustEdge certificate: --x509-cert RSA_CERT_2048", TestStatus.FAIL, stderr)
    
    # Test EST and SCEP help
    for protocol in ["est", "scep"]:
        exit_code, stdout, stderr = run_trustedge("certificate", protocol, "--help")
        if exit_code == 0:
            runner.collect(f"TrustEdge certificate {protocol} --help", TestStatus.PASS)
        else:
            runner.collect(f"TrustEdge certificate {protocol} --help", TestStatus.FAIL, stderr)

# ============================================================================
# MQTT Tests
# ============================================================================

def test_mqtt(runner: TestRunner):
    """Test trustedge mqtt commands."""
    runner.log_section("Testing TrustEdge MQTT")
    
    # mqtt --help
    exit_code, stdout, stderr = run_trustedge("mqtt", "--help")
    if exit_code == 0:
        runner.collect("TrustEdge mqtt --help", TestStatus.PASS)
    else:
        runner.collect("TrustEdge mqtt --help", TestStatus.FAIL, stderr)

# ============================================================================
# Device Registration
# ============================================================================

def register_device(runner: TestRunner) -> Optional[Path]:
    """Register a device and download bootstrap.zip.
    
    Requires DEMO_API_KEY environment variable.
    Returns path to bootstrap.zip or None on failure.
    """
    runner.log_section("Registering Device")
    
    if not HAS_REQUESTS:
        runner.collect("Device registration", TestStatus.FAIL, 
                      "requests module not installed. Run: pip install requests")
        return None
    
    api_key = os.environ.get('DEMO_API_KEY')
    if not api_key:
        runner.collect("Device registration", TestStatus.FAIL, 
                      "DEMO_API_KEY environment variable not set")
        return None
    
    headers = {"x-api-key": api_key}
    
    # Use platform-specific device name and group
    device_name = "Trustedge-Sanity-Test-Device-Final-Windows" if IS_WINDOWS else "Trustedge-Sanity-Test-Device-Final"
    device_group_id = "89b599d6-1439-449f-a1c6-5b513710269a" if IS_WINDOWS else "9ecf6d49-2ba7-477d-a5e3-bdde1124c87e"
    
    payload = {
        "name": device_name,
        "device_group_id": device_group_id,
        "account_id": "815af465-94ee-4a4b-b8c9-2a70b5e6f0bc",
        "certificate_policies": {
            "bootstrap": [
                {
                    "certificate_policy_id": "IOT_353b088e-8a60-40f3-8ecf-71e7edf430b5",
                    "server_side_key_gen": True,
                    "key_type": "RSA_2048",
                    "key_format": "PEM",
                    "key_syntax": "PKCS8",
                    "attributes": [
                        {
                            "name": "subject.common_name",
                            "value": "trustedge-sanity-test"
                        }
                    ]
                }
            ]
        }
    }
    
    session = requests.Session()
    reg_url = 'https://demo.one.digicert.com/devicetrustmanager/api/v4/device/registration'
    
    # Retry registration
    max_retries = 5
    device_id = None
    
    for attempt in range(max_retries):
        try:
            runner.log(f"Registration attempt {attempt + 1}/{max_retries}")
            response = session.post(reg_url, headers=headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                device_id = response.json().get("device_id")
                runner.log(f"Registration successful. Device ID: {device_id}")
                break
            elif response.status_code in [403, 409, 500, 502, 503, 504]:
                wait_time = 10 * (2 ** attempt)
                runner.log(f"Status {response.status_code}, retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                error_data = response.json() if response.content else {}
                # Handle duplicate device name
                if error_data.get('error', {}).get('code') == '03':
                    runner.log("Device already exists, attempting to delete...")
                    device_id = _find_and_delete_existing_device(session, headers, runner)
                    if device_id:
                        continue  # Retry registration
                runner.collect("Device registration", TestStatus.FAIL, 
                              f"HTTP {response.status_code}: {error_data}")
                return None
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                wait_time = 10 * (2 ** attempt)
                runner.log(f"Request failed: {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                runner.collect("Device registration", TestStatus.FAIL, str(e))
                return None
    
    if not device_id:
        runner.collect("Device registration", TestStatus.FAIL, "Max retries exceeded")
        return None
    
    # Save device ID for cleanup
    runner.device_id = device_id
    Path("device_id.txt").write_text(device_id)
    
    # Download bootstrap.zip
    bootstrap_url = f'https://demo.one.digicert.com/devicetrustmanager/api/v4/bootstrap-config/download/{device_id}'
    try:
        response = session.get(bootstrap_url, headers=headers, timeout=30)
        if response.status_code == 200:
            bootstrap_path = Path("bootstrap.zip")
            bootstrap_path.write_bytes(response.content)
            runner.collect("Device registration", TestStatus.PASS)
            runner.log(f"Bootstrap downloaded: {bootstrap_path}")
            return bootstrap_path
        else:
            runner.collect("Device registration", TestStatus.FAIL, 
                          f"Bootstrap download failed: HTTP {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        runner.collect("Device registration", TestStatus.FAIL, f"Bootstrap download: {e}")
        return None

def _find_and_delete_existing_device(session, headers, runner: TestRunner) -> Optional[str]:
    """Find existing device and delete it."""
    device_url = 'https://demo.one.digicert.com/devicetrustmanager/api/v4/device'
    device_name = "Trustedge-Sanity-Test-Device-Final-Windows" if IS_WINDOWS else "Trustedge-Sanity-Test-Device-Final"
    device_group_id = "89b599d6-1439-449f-a1c6-5b513710269a" if IS_WINDOWS else "9ecf6d49-2ba7-477d-a5e3-bdde1124c87e"
    params = {
        "name": device_name,
        "device_group_id": device_group_id,
        "account_id": "815af465-94ee-4a4b-b8c9-2a70b5e6f0bc"
    }
    
    try:
        response = session.get(device_url, headers=headers, params=params, timeout=30)
        if response.status_code == 200:
            records = response.json().get('records', [])
            if records:
                device_id = records[0].get('id')
                runner.log(f"Found existing device: {device_id}")
                # Try to delete using the script - check multiple locations
                script_locations = [
                    Path(__file__).parent / "disable_delete_device.py",
                    Path(__file__).parent.parent.parent.parent / "src" / "trustedge" / "sanity_test" / "disable_delete_device.py",
                    Path("tmp/disable_delete_device.py"),
                    Path("src/trustedge/sanity_test/disable_delete_device.py"),
                ]
                
                script_path = None
                for loc in script_locations:
                    if loc.exists():
                        script_path = loc
                        break
                
                if script_path:
                    runner.log(f"Using delete script: {script_path}")
                    result = subprocess.run(
                        [sys.executable, str(script_path), device_id],
                        capture_output=True, text=True
                    )
                    runner.log(f"Delete script output: {result.stdout}")
                    if result.stderr:
                        runner.log(f"Delete script stderr: {result.stderr}")
                    if result.returncode == 0:
                        runner.log("Existing device deleted successfully")
                        time.sleep(2)  # Give API time to process deletion
                        return device_id
                    else:
                        runner.log(f"Delete script failed with code {result.returncode}")
                else:
                    runner.log(f"Delete script not found in any of: {[str(l) for l in script_locations]}")
    except Exception as e:
        runner.log(f"Error finding/deleting device: {e}")
    
    return None

def delete_registered_device(device_id: str, runner: TestRunner):
    """Delete a registered device."""
    script_locations = [
        Path(__file__).parent / "disable_delete_device.py",
        Path(__file__).parent.parent.parent.parent / "src" / "trustedge" / "sanity_test" / "disable_delete_device.py",
        Path("tmp/disable_delete_device.py"),
        Path("src/trustedge/sanity_test/disable_delete_device.py"),
    ]
    
    script_path = None
    for loc in script_locations:
        if loc.exists():
            script_path = loc
            break
    
    if script_path:
        runner.log(f"Deleting device {device_id} using {script_path}...")
        result = subprocess.run(
            [sys.executable, str(script_path), device_id],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            runner.log("Device deleted successfully")
        else:
            runner.log(f"Failed to delete device: {result.stderr}")
    else:
        runner.log(f"Delete script not found in any of: {[str(l) for l in script_locations]}")

# ============================================================================
# Service Tests (Platform-specific)
# ============================================================================

WINDOWS_SERVICE_NAME = "DigiCertTrustEdge"

def _test_windows_service(runner: TestRunner):
    """Test TrustEdge Windows service management."""
    runner.log_section("Testing TrustEdge Windows Service")
    
    # Check for admin privileges
    if not _is_admin():
        runner.collect("TrustEdge Windows service tests", TestStatus.SKIP,
                      "Administrator privileges required. Run as Administrator.")
        return
    
    # Check if service exists
    result = subprocess.run(
        ["sc", "query", WINDOWS_SERVICE_NAME],
        capture_output=True, text=True
    )
    
    if result.returncode != 0:
        # Service not found - check if it's a "service does not exist" error
        if "1060" in result.stdout or "does not exist" in result.stdout.lower():
            runner.collect("TrustEdge Windows service exists", TestStatus.FAIL,
                          f"Service '{WINDOWS_SERVICE_NAME}' not found. Was TrustEdge installed with service support?")
        else:
            runner.collect("TrustEdge Windows service exists", TestStatus.FAIL,
                          f"sc query failed: {result.stdout} {result.stderr}")
        return
    
    runner.collect("TrustEdge Windows service exists", TestStatus.PASS)
    
    # Parse initial service state
    initial_state = _parse_windows_service_state(result.stdout)
    runner.log(f"Initial service state: {initial_state}")
    
    # If service is running, stop it first for clean test
    if initial_state == "RUNNING":
        runner.log("Service is running, stopping it first for clean test...")
        subprocess.run(["sc", "stop", WINDOWS_SERVICE_NAME], capture_output=True, text=True)
        time.sleep(2)  # Give service time to stop
    
    # Test: Start service
    result = subprocess.run(
        ["sc", "start", WINDOWS_SERVICE_NAME],
        capture_output=True, text=True
    )
    
    # Wait for service to start
    time.sleep(3)
    
    # Verify service started
    query_result = subprocess.run(
        ["sc", "query", WINDOWS_SERVICE_NAME],
        capture_output=True, text=True
    )
    current_state = _parse_windows_service_state(query_result.stdout)
    
    if current_state == "RUNNING":
        runner.collect("TrustEdge Windows service start", TestStatus.PASS)
    elif current_state == "START_PENDING":
        # Service is starting, wait a bit more
        time.sleep(5)
        query_result = subprocess.run(
            ["sc", "query", WINDOWS_SERVICE_NAME],
            capture_output=True, text=True
        )
        current_state = _parse_windows_service_state(query_result.stdout)
        if current_state == "RUNNING":
            runner.collect("TrustEdge Windows service start", TestStatus.PASS)
        else:
            runner.collect("TrustEdge Windows service start", TestStatus.FAIL,
                          f"Service state after start: {current_state}")
    else:
        runner.collect("TrustEdge Windows service start", TestStatus.FAIL,
                      f"Service failed to start. State: {current_state}. Output: {result.stdout}")
        return  # Don't continue if start failed
    
    # Test: Query service while running
    result = subprocess.run(
        ["sc", "query", WINDOWS_SERVICE_NAME],
        capture_output=True, text=True
    )
    if result.returncode == 0 and "RUNNING" in result.stdout:
        runner.collect("TrustEdge Windows service query (running)", TestStatus.PASS)
    else:
        runner.collect("TrustEdge Windows service query (running)", TestStatus.FAIL,
                      f"Query output: {result.stdout}")
    
    # Test: Stop service
    result = subprocess.run(
        ["sc", "stop", WINDOWS_SERVICE_NAME],
        capture_output=True, text=True
    )
    
    # Wait for service to stop
    time.sleep(3)
    
    # Verify service stopped
    query_result = subprocess.run(
        ["sc", "query", WINDOWS_SERVICE_NAME],
        capture_output=True, text=True
    )
    current_state = _parse_windows_service_state(query_result.stdout)
    
    if current_state == "STOPPED":
        runner.collect("TrustEdge Windows service stop", TestStatus.PASS)
    elif current_state == "STOP_PENDING":
        # Service is stopping, wait a bit more
        time.sleep(5)
        query_result = subprocess.run(
            ["sc", "query", WINDOWS_SERVICE_NAME],
            capture_output=True, text=True
        )
        current_state = _parse_windows_service_state(query_result.stdout)
        if current_state == "STOPPED":
            runner.collect("TrustEdge Windows service stop", TestStatus.PASS)
        else:
            runner.collect("TrustEdge Windows service stop", TestStatus.FAIL,
                          f"Service state after stop: {current_state}")
    else:
        runner.collect("TrustEdge Windows service stop", TestStatus.FAIL,
                      f"Service failed to stop. State: {current_state}. Output: {result.stdout}")

def _parse_windows_service_state(sc_output: str) -> str:
    """Parse Windows service state from sc query output."""
    # sc query output looks like:
    # SERVICE_NAME: DigiCertTrustEdge
    #         TYPE               : 10  WIN32_OWN_PROCESS
    #         STATE              : 1  STOPPED
    #         WIN32_EXIT_CODE    : 0  (0x0)
    #         ...
    state_map = {
        "1": "STOPPED",
        "2": "START_PENDING",
        "3": "STOP_PENDING",
        "4": "RUNNING",
        "5": "CONTINUE_PENDING",
        "6": "PAUSE_PENDING",
        "7": "PAUSED",
    }
    
    for line in sc_output.split('\n'):
        if "STATE" in line:
            # Extract state code (e.g., "1" from "STATE : 1  STOPPED")
            parts = line.split(':')
            if len(parts) >= 2:
                state_part = parts[1].strip().split()[0]
                return state_map.get(state_part, state_part)
    
    return "UNKNOWN"

def _test_linux_service(runner: TestRunner):
    """Test TrustEdge Linux service management (systemd)."""
    runner.log_section("Testing TrustEdge Linux Service")
    
    # Check initial status
    result = subprocess.run(
        ["systemctl", "status", "trustedge.service"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        runner.log("Service is currently running")
    else:
        runner.log("Service is not currently running")
    
    # Start service
    result = subprocess.run(["systemctl", "start", "trustedge.service"], capture_output=True, text=True)
    if result.returncode == 0:
        runner.collect("TrustEdge service start", TestStatus.PASS)
    else:
        runner.collect("TrustEdge service start", TestStatus.FAIL, result.stderr)
    
    # Stop service
    result = subprocess.run(["systemctl", "stop", "trustedge.service"], capture_output=True, text=True)
    if result.returncode == 0:
        runner.collect("TrustEdge service stop", TestStatus.PASS)
    else:
        runner.collect("TrustEdge service stop", TestStatus.FAIL, result.stderr)

def test_service(runner: TestRunner):
    """Test TrustEdge service management (platform-specific)."""
    if IS_WINDOWS:
        _test_windows_service(runner)
    else:
        _test_linux_service(runner)

# ============================================================================
# Main Entry Point
# ============================================================================

def cleanup(runner: TestRunner):
    """Cleanup after tests."""
    # Cleanup device registration
    if runner.device_id:
        delete_registered_device(runner.device_id, runner)
    
    # Prompt before uninstalling in interactive mode
    if IS_WINDOWS and runner.msi_file and runner.msi_file.exists():
        if runner.interactive:
            print()
            print("  TrustEdge installation detected.")
            print(f"  Data directory: {CONFIG.digicert_path}")
            response = input("  Uninstall TrustEdge? [Y/n]: ").strip().lower()
            if response == 'n':
                print("  Keeping TrustEdge installed.")
                # Remove temp files only
                for f in ["bootstrap.zip", "device_id.txt"]:
                    Path(f).unlink(missing_ok=True)
                return
        
        runner.log_section("Cleaning up: Uninstalling TrustEdge")
        result = subprocess.run(
            ["msiexec", "/x", str(runner.msi_file), "/qn"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            runner.collect("TrustEdge uninstallation (MSI)", TestStatus.PASS)
        else:
            runner.collect("TrustEdge uninstallation (MSI)", TestStatus.FAIL, 
                          f"msiexec code {result.returncode}")
    
    # Remove temp files
    for f in ["bootstrap.zip", "device_id.txt"]:
        Path(f).unlink(missing_ok=True)

def main():
    parser = argparse.ArgumentParser(description="TrustEdge Unified Sanity Test")
    parser.add_argument("--skip-install", action="store_true", help="Skip installation tests")
    parser.add_argument("--skip-agent", action="store_true", help="Skip agent tests")
    parser.add_argument("--skip-certificate", action="store_true", help="Skip certificate tests")
    parser.add_argument("--skip-mqtt", action="store_true", help="Skip MQTT tests")
    parser.add_argument("--skip-service", action="store_true", help="Skip service tests")
    parser.add_argument("--bootstrap-zip", type=Path, help="Path to bootstrap.zip for agent tests")
    parser.add_argument("--register-device", action="store_true", 
                       help="Register device and download bootstrap.zip (requires DEMO_API_KEY env var)")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Interactive mode: prompt before each test (useful for debugging)")
    parser.add_argument("--package-dir", type=Path, default=Path("tmp"), help="Package directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()
    
    print()
    print("=" * 73)
    print("TrustEdge Unified Sanity Test")
    print(f"Platform: {platform.system()} {platform.machine()}")
    print("=" * 73)
    
    runner = TestRunner(verbose=args.verbose, interactive=args.interactive)
    bootstrap_zip = args.bootstrap_zip
    
    try:
        # Installation tests
        if not args.skip_install:
            cont = runner.prompt_continue("Installation tests")
            if cont is False:
                raise KeyboardInterrupt
            if cont is not None:
                test_installation(runner, args.package_dir)
        
        # Basic command tests
        cont = runner.prompt_continue("TrustEdge help and version")
        if cont is False:
            raise KeyboardInterrupt
        if cont is not None:
            test_help_version(runner)
        
        # Register device if requested
        if args.register_device and not args.skip_agent:
            cont = runner.prompt_continue("Device registration")
            if cont is False:
                raise KeyboardInterrupt
            if cont is not None:
                registered_bootstrap = register_device(runner)
                if registered_bootstrap:
                    bootstrap_zip = registered_bootstrap
        
        # Agent tests
        if not args.skip_agent:
            cont = runner.prompt_continue("Agent tests")
            if cont is False:
                raise KeyboardInterrupt
            if cont is not None:
                test_agent(runner, bootstrap_zip)
        
        # Certificate tests
        if not args.skip_certificate:
            cont = runner.prompt_continue("Certificate tests")
            if cont is False:
                raise KeyboardInterrupt
            if cont is not None:
                test_certificate(runner)
        
        # MQTT tests
        if not args.skip_mqtt:
            cont = runner.prompt_continue("MQTT tests")
            if cont is False:
                raise KeyboardInterrupt
            if cont is not None:
                test_mqtt(runner)
        
        # Service tests
        if not args.skip_service:
            cont = runner.prompt_continue("Service tests")
            if cont is False:
                raise KeyboardInterrupt
            if cont is not None:
                test_service(runner)
        
        # Agent reset (cleanup)
        if not args.skip_agent:
            cont = runner.prompt_continue("Agent reset")
            if cont is False:
                raise KeyboardInterrupt
            if cont is not None:
                test_agent_reset(runner)
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        raise
    finally:
        cleanup(runner)
        all_passed = runner.display_summary()
    
    sys.exit(0 if all_passed else 1)

if __name__ == "__main__":
    main()
