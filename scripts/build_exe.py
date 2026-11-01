"""Automated build script for NetSentinel AI single-file executable.

Invokes PyInstaller using netsentinel.spec, verifies the resulting binary,
and runs automated self-tests on the generated NetSentinelAI.exe.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent.parent
    spec_file = project_root / "netsentinel.spec"
    dist_dir = project_root / "dist"
    build_dir = project_root / "build"
    output_exe = dist_dir / "NetSentinelAI.exe"

    print("=" * 65)
    print("NetSentinel AI - Single-File Portable Executable Builder")
    print("=" * 65)
    print(f"[*] Project root: {project_root}")
    print(f"[*] Spec file:    {spec_file}")

    if not spec_file.exists():
        print(f"[!] Error: Spec file '{spec_file}' not found.", file=sys.stderr)
        return 1

    # Clean previous builds
    print("[*] Cleaning build artifacts...")
    if build_dir.exists():
        shutil.rmtree(build_dir, ignore_errors=True)
    if output_exe.exists():
        output_exe.unlink(missing_ok=True)

    # Determine PyInstaller executable
    pyinstaller_cmd = [sys.executable, "-m", "PyInstaller", str(spec_file), "--noconfirm"]

    print(f"[*] Executing PyInstaller: {' '.join(pyinstaller_cmd)}")
    result = subprocess.run(pyinstaller_cmd, cwd=str(project_root))
    if result.returncode != 0:
        print(f"[!] PyInstaller build failed with exit code {result.returncode}", file=sys.stderr)
        return result.returncode

    if not output_exe.exists():
        print(f"[!] Build error: Expected output '{output_exe}' was not created.", file=sys.stderr)
        return 1

    exe_size_mb = output_exe.stat().st_size / (1024 * 1024)
    print("-" * 65)
    print(f"[+] Build succeeded!")
    print(f"[+] Output artifact: {output_exe}")
    print(f"[+] Executable size: {exe_size_mb:.2f} MB")
    print("-" * 65)

    # Automated verification of built artifact
    print("[*] Running verification test 1: Health Check on built executable...")
    test1 = subprocess.run(
        [str(output_exe), "--health-check"],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=30,
    )
    print(test1.stdout)
    if test1.returncode != 0:
        print(f"[!] Health check failed with code {test1.returncode}: {test1.stderr}", file=sys.stderr)
        return test1.returncode
    print("[+] Test 1 passed: Standard health check OK.")

    print("\n[*] Running verification test 2: Portable Mode on built executable...")
    test2 = subprocess.run(
        [str(output_exe), "--portable", "--health-check"],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=30,
    )
    print(test2.stdout)
    if test2.returncode != 0:
        print(f"[!] Portable mode check failed with code {test2.returncode}: {test2.stderr}", file=sys.stderr)
        return test2.returncode
    print("[+] Test 2 passed: Portable mode health check OK.")

    print("=" * 65)
    print("[+] ALL VERIFICATION TESTS PASSED FOR NetSentinelAI.exe!")
    print("=" * 65)
    return 0


if __name__ == "__main__":
    sys.exit(main())
