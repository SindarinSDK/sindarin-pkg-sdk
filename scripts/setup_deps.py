#!/usr/bin/env python3
"""
Cross-platform dependency setup for Sindarin SDK.

This script installs dependencies for static linking via vcpkg.

Usage:
    python scripts/setup_deps.py [options]

Options:
    --vcpkg-root PATH  Path to vcpkg installation (default: ./vcpkg)
    --check            Check if dependencies are installed (don't install)
    --verbose          Show detailed output
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, List, Tuple


def is_windows() -> bool:
    return platform.system() == 'Windows'


def is_macos() -> bool:
    return platform.system() == 'Darwin'


def is_linux() -> bool:
    return platform.system() == 'Linux'


def run_command(cmd: List[str], check: bool = True, capture: bool = False,
                env: Optional[dict] = None, cwd: Optional[str] = None) -> Tuple[int, str, str]:
    """Run a command and return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture,
            text=True,
            env=env or os.environ,
            cwd=cwd
        )
        return 0, result.stdout or '', result.stderr or ''
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout or '', e.stderr or ''
    except FileNotFoundError:
        return -1, '', f'Command not found: {cmd[0]}'


def find_executable(name: str) -> Optional[str]:
    """Find an executable in PATH."""
    return shutil.which(name)


class DependencyChecker:
    """Check for required dependencies."""

    # All known tools
    ALL_TOOLS = {
        'cmake': ('cmake', '--version'),
        'git': ('git', '--version'),
        'curl': ('curl', '--version'),
        'zip': ('zip', '--version'),
        'unzip': ('unzip', '-v'),
        'tar': ('tar', '--version'),
        'pkg-config': ('pkg-config', '--version'),
        'ninja': ('ninja', '--version'),
    }

    # Platform-specific required tools
    # On Windows, vcpkg uses PowerShell for archives and doesn't need pkg-config
    REQUIRED_TOOLS_WINDOWS = ['cmake', 'git']
    REQUIRED_TOOLS_UNIX = ['cmake', 'git', 'curl', 'zip', 'unzip', 'tar', 'pkg-config']

    # Optional but recommended tools
    OPTIONAL_TOOLS = ['ninja']

    REQUIRED_COMPILERS = {
        'gcc': ('gcc', '--version'),
        'clang': ('clang', '--version'),
    }

    def get_required_tools(self) -> List[str]:
        """Get list of required tools for current platform."""
        if is_windows():
            return self.REQUIRED_TOOLS_WINDOWS
        return self.REQUIRED_TOOLS_UNIX

    def check_tool(self, name: str) -> bool:
        """Check if a tool is available."""
        if name not in self.ALL_TOOLS:
            return find_executable(name) is not None

        cmd_name, version_arg = self.ALL_TOOLS[name]
        path = find_executable(cmd_name)
        if not path:
            return False

        exit_code, _, _ = run_command([path, version_arg], check=False, capture=True)
        return exit_code == 0

    def check_compiler(self) -> Tuple[bool, str]:
        """Check if at least one compiler is available."""
        for name, (cmd, arg) in self.REQUIRED_COMPILERS.items():
            path = find_executable(cmd)
            if path:
                exit_code, _, _ = run_command([path, arg], check=False, capture=True)
                if exit_code == 0:
                    return True, name
        return False, ''

    def check_all(self, verbose: bool = False) -> bool:
        """Check all dependencies."""
        all_ok = True

        required_tools = self.get_required_tools()

        print("Checking build tools...")
        for tool in required_tools:
            ok = self.check_tool(tool)
            status = 'OK' if ok else 'MISSING'
            print(f"  {tool}: {status}")
            if not ok:
                all_ok = False

        # Check optional tools
        for tool in self.OPTIONAL_TOOLS:
            ok = self.check_tool(tool)
            status = 'OK' if ok else 'MISSING (optional)'
            print(f"  {tool}: {status}")

        print("\nChecking compilers...")
        compiler_ok, compiler_name = self.check_compiler()
        if compiler_ok:
            print(f"  Found: {compiler_name}")
        else:
            print("  No C compiler found (need gcc or clang)")
            all_ok = False

        return all_ok


class VcpkgInstaller:
    """Install dependencies using vcpkg on any platform."""

    def __init__(self, vcpkg_root: Optional[str] = None):
        if vcpkg_root:
            self.vcpkg_root = os.path.abspath(vcpkg_root)
        else:
            # Default to vcpkg/ in project root
            self.vcpkg_root = os.path.join(os.getcwd(), 'vcpkg')

        self.verbose = False

    def get_triplet(self) -> str:
        """Get the vcpkg triplet for the current platform."""
        if is_windows():
            # Use MinGW static triplet for self-contained executables
            return 'x64-mingw-static'
        elif is_macos():
            # Check architecture
            machine = platform.machine()
            if machine == 'arm64':
                return 'arm64-osx'
            return 'x64-osx'
        else:
            # Linux - use static linking for self-contained executables
            return 'x64-linux'

    def get_vcpkg_exe(self) -> str:
        """Get the vcpkg executable path."""
        if is_windows():
            return os.path.join(self.vcpkg_root, 'vcpkg.exe')
        else:
            return os.path.join(self.vcpkg_root, 'vcpkg')

    def setup(self) -> bool:
        """Clone and bootstrap vcpkg."""
        if os.path.isdir(self.vcpkg_root) and os.path.isfile(self.get_vcpkg_exe()):
            print(f"vcpkg already bootstrapped at: {self.vcpkg_root}")
            return True

        if os.path.isdir(self.vcpkg_root):
            print(f"vcpkg directory exists, bootstrapping...")
        else:
            print("Cloning vcpkg...")
            cmd = ['git', 'clone', 'https://github.com/microsoft/vcpkg.git', self.vcpkg_root]
            exit_code, stdout, stderr = run_command(cmd, check=False, capture=True)
            if exit_code != 0:
                print(f"Error cloning vcpkg: {stderr}")
                return False

        print("Bootstrapping vcpkg...")
        if is_windows():
            bootstrap = os.path.join(self.vcpkg_root, 'bootstrap-vcpkg.bat')
            cmd = [bootstrap, '-disableMetrics']
        else:
            bootstrap = os.path.join(self.vcpkg_root, 'bootstrap-vcpkg.sh')
            cmd = ['sh', bootstrap, '-disableMetrics']

        exit_code, stdout, stderr = run_command(cmd, check=False, capture=not self.verbose, cwd=self.vcpkg_root)
        if exit_code != 0:
            print(f"Error bootstrapping vcpkg: {stderr}")
            return False

        print("vcpkg bootstrapped successfully!")
        return True

    def install_packages(self) -> bool:
        """Install packages using vcpkg."""
        vcpkg_exe = self.get_vcpkg_exe()

        if not os.path.isfile(vcpkg_exe):
            print("Error: vcpkg not found")
            return False

        triplet = self.get_triplet()

        # Check if there's a vcpkg.json manifest in the project root
        project_root = os.path.dirname(self.vcpkg_root)
        manifest_path = os.path.join(project_root, 'vcpkg.json')

        if os.path.isfile(manifest_path):
            # Manifest mode: run vcpkg install with triplet from project root
            print(f"\nInstalling packages from vcpkg.json for triplet: {triplet}")
            print("This will compile packages from source...")

            cmd = [vcpkg_exe, 'install', f'--triplet={triplet}']

            if self.verbose:
                exit_code, _, _ = run_command(cmd, check=False, capture=False, cwd=project_root)
            else:
                exit_code, stdout, stderr = run_command(cmd, check=False, capture=True, cwd=project_root)
                if exit_code != 0:
                    print(f"Error installing packages:")
                    print(stderr or stdout)
                    return False

            if exit_code != 0:
                print("Failed to install packages")
                return False

            print("Packages installed successfully")
        else:
            # Classic mode: install individual packages
            packages = [f'zlib:{triplet}', f'yyjson:{triplet}']

            print(f"\nInstalling packages for triplet: {triplet}")
            print("This will compile packages from source...")

            for package in packages:
                print(f"\nInstalling {package}...")
                cmd = [vcpkg_exe, 'install', package]

                if self.verbose:
                    exit_code, _, _ = run_command(cmd, check=False, capture=False)
                else:
                    exit_code, stdout, stderr = run_command(cmd, check=False, capture=True)
                    if exit_code != 0:
                        print(f"Error installing {package}:")
                        print(stderr or stdout)
                        return False

                if exit_code != 0:
                    print(f"Failed to install {package}")
                    return False

                print(f"  {package} installed successfully")

        return True

    def get_installed_dir(self) -> str:
        """Get the path to installed packages."""
        triplet = self.get_triplet()

        # Check if manifest mode (vcpkg_installed in project root)
        project_root = os.path.dirname(self.vcpkg_root)
        manifest_installed = os.path.join(project_root, 'vcpkg_installed', triplet)
        if os.path.isdir(manifest_installed):
            return manifest_installed

        # Classic mode (installed in vcpkg directory)
        return os.path.join(self.vcpkg_root, 'installed', triplet)

    def verify_installation(self) -> bool:
        """Verify that packages are correctly installed."""
        installed_dir = self.get_installed_dir()

        print(f"\nVerifying installation in: {installed_dir}")

        # Check for required headers
        include_dir = os.path.join(installed_dir, 'include')
        required_headers = ['zlib.h', 'yyjson.h', 'libxml2/libxml/parser.h', 'yaml.h', 'git2.h']

        for header in required_headers:
            header_path = os.path.join(include_dir, header)
            if os.path.isfile(header_path):
                print(f"  {header}: OK")
            else:
                print(f"  {header}: MISSING")
                return False

        # Check for libraries
        lib_dir = os.path.join(installed_dir, 'lib')

        # Define library patterns to search for each dependency
        # We check multiple possible names since vcpkg naming varies by triplet
        lib_patterns = {
            'zlib': ['libz.a', 'libzlib.a', 'libzlib.dll.a', 'libz.dll.a', 'z.lib', 'zlib.lib',
                     'libz.so', 'libz.dylib'],
            'yyjson': ['libyyjson.a', 'libyyjson.dll.a', 'yyjson.lib',
                       'libyyjson.so', 'libyyjson.dylib'],
            'libxml2': ['libxml2.a', 'libxml2.dll.a', 'xml2.lib', 'libxml2.lib',
                        'libxml2.so', 'libxml2.dylib'],
            'libyaml': ['libyaml.a', 'libyaml.dll.a', 'yaml.lib', 'libyaml.lib',
                        'libyaml.so', 'libyaml.dylib'],
            'openssl': ['libssl.a', 'libssl.dll.a', 'ssl.lib', 'libssl.lib',
                        'libssl.so', 'libssl.dylib'],
            'libgit2': ['libgit2.a', 'libgit2.dll.a', 'git2.lib', 'libgit2.lib',
                        'libgit2.so', 'libgit2.dylib'],
        }

        for dep_name, patterns in lib_patterns.items():
            found = False
            found_name = None
            for pattern in patterns:
                lib_path = os.path.join(lib_dir, pattern)
                if os.path.isfile(lib_path):
                    found = True
                    found_name = pattern
                    break
            # Also check for versioned .so files
            if not found and os.path.isdir(lib_dir):
                for f in os.listdir(lib_dir):
                    if f.startswith(f'lib{dep_name}') and ('.so' in f or '.dylib' in f or '.a' in f):
                        found = True
                        found_name = f
                        break
            if found:
                print(f"  {dep_name}: OK ({found_name})")
            else:
                print(f"  {dep_name}: MISSING")
                return False

        return True

    def install(self, verbose: bool = False) -> bool:
        """Full vcpkg setup and package installation."""
        self.verbose = verbose

        if not self.setup():
            return False
        if not self.install_packages():
            return False
        if not self.verify_installation():
            return False

        # Print helpful info
        installed_dir = self.get_installed_dir()
        print(f"\n" + "=" * 60)
        print("Dependencies installed successfully!")
        print(f"=" * 60)
        print(f"\nVCPKG installed packages to: {installed_dir}")
        print(f"  Include dir: {os.path.join(installed_dir, 'include')}")
        print(f"  Library dir: {os.path.join(installed_dir, 'lib')}")
        print(f"\nTo use these dependencies, run 'make build' which will")
        print("automatically detect and use the vcpkg packages.")

        return True


def install_build_tools():
    """Install basic build tools if missing."""
    checker = DependencyChecker()

    missing_required = []
    missing_optional = []
    for tool in checker.get_required_tools():
        if not checker.check_tool(tool):
            missing_required.append(tool)
    for tool in checker.OPTIONAL_TOOLS:
        if not checker.check_tool(tool):
            missing_optional.append(tool)

    if not missing_required and not missing_optional:
        return True

    all_missing = missing_required + missing_optional
    if not all_missing:
        return True

    print(f"\nInstalling missing tools: {', '.join(all_missing)}")

    if is_linux():
        # Detect package manager and actually install
        if find_executable('apt-get'):
            pkg_map = {'cmake': 'cmake', 'ninja': 'ninja-build', 'git': 'git',
                       'curl': 'curl', 'zip': 'zip', 'unzip': 'unzip', 'tar': 'tar',
                       'pkg-config': 'pkg-config'}
            packages = [pkg_map.get(t, t) for t in all_missing]

            print("Updating package lists...")
            run_command(['sudo', 'apt-get', 'update'], check=False)

            cmd = ['sudo', 'apt-get', 'install', '-y'] + packages
            print(f"Installing: {', '.join(packages)}")
            exit_code, _, _ = run_command(cmd, check=False)
            return exit_code == 0

        elif find_executable('dnf'):
            pkg_map = {'cmake': 'cmake', 'ninja': 'ninja-build', 'git': 'git',
                       'curl': 'curl', 'zip': 'zip', 'unzip': 'unzip', 'tar': 'tar',
                       'pkg-config': 'pkg-config'}
            packages = [pkg_map.get(t, t) for t in all_missing]

            cmd = ['sudo', 'dnf', 'install', '-y'] + packages
            print(f"Installing: {', '.join(packages)}")
            exit_code, _, _ = run_command(cmd, check=False)
            return exit_code == 0

        elif find_executable('pacman'):
            pkg_map = {'cmake': 'cmake', 'ninja': 'ninja', 'git': 'git',
                       'curl': 'curl', 'zip': 'zip', 'unzip': 'unzip', 'tar': 'tar',
                       'pkg-config': 'pkgconf'}
            packages = [pkg_map.get(t, t) for t in all_missing]

            cmd = ['sudo', 'pacman', '-S', '--noconfirm'] + packages
            print(f"Installing: {', '.join(packages)}")
            exit_code, _, _ = run_command(cmd, check=False)
            return exit_code == 0
        else:
            print("Error: No supported package manager found (apt, dnf, pacman)")
            return False

    elif is_macos():
        if find_executable('brew'):
            cmd = ['brew', 'install'] + all_missing
            print(f"Installing: {', '.join(all_missing)}")
            exit_code, _, _ = run_command(cmd, check=False)
            return exit_code == 0
        else:
            print("Error: Homebrew not found. Install from https://brew.sh")
            return False

    elif is_windows():
        print("Windows: Please install missing tools manually:")
        if 'cmake' in all_missing:
            print("  CMake: https://cmake.org/download/")
        if 'ninja' in all_missing:
            print("  Ninja: https://github.com/ninja-build/ninja/releases")
        if 'git' in all_missing:
            print("  Git: https://git-scm.com/download/win")
        return False

    return False


def main():
    parser = argparse.ArgumentParser(
        description='Cross-platform dependency setup for Sindarin SDK using vcpkg'
    )
    parser.add_argument('--vcpkg-root', help='Path to vcpkg installation (default: ./vcpkg)')
    parser.add_argument('--check', action='store_true',
                       help='Check dependencies without installing')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Show detailed output')

    args = parser.parse_args()

    print(f"Platform: {platform.system()} ({platform.machine()})")
    print()

    checker = DependencyChecker()

    if args.check:
        # Check dependencies
        if checker.check_all(args.verbose):
            # Also check vcpkg packages
            installer = VcpkgInstaller(args.vcpkg_root)
            if os.path.isdir(installer.get_installed_dir()):
                print("\nChecking vcpkg packages...")
                if installer.verify_installation():
                    print("\nAll dependencies are installed!")
                    sys.exit(0)
                else:
                    print("\nvcpkg packages need to be installed.")
                    sys.exit(1)
            else:
                print("\nvcpkg packages not yet installed.")
                sys.exit(1)
        else:
            print("\nSome build tools are missing.")
            sys.exit(1)

    # Check build tools first
    if not checker.check_all(args.verbose):
        print()
        if not install_build_tools():
            sys.exit(1)
        # Re-check after instructions
        if not checker.check_all(False):
            print("\nPlease install the missing tools and run this script again.")
            sys.exit(1)

    # Install dependencies using vcpkg
    print("\n" + "=" * 60)
    print("Setting up vcpkg and installing dependencies...")
    print("=" * 60 + "\n")

    installer = VcpkgInstaller(args.vcpkg_root)
    success = installer.install(args.verbose)

    if success:
        print("\nSetup completed successfully!")
        sys.exit(0)
    else:
        print("\nSetup encountered errors.")
        sys.exit(1)


if __name__ == '__main__':
    main()
