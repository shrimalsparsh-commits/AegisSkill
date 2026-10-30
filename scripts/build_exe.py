"""Build script to compile AegisSkill into a standalone Windows .exe using PyInstaller."""

from pathlib import Path
import subprocess
import sys


def build():
    root_dir = Path(__file__).resolve().parent.parent
    spec_file = root_dir / "build.spec"

    print("=================================================================")
    print("   AEGIS-SKILL : STANDALONE EXECUTABLE BUILD SCRIPT")
    print("=================================================================")
    print(f"Project Root : {root_dir}")
    print(f"Spec File    : {spec_file}")

    if not spec_file.exists():
        print(f"Error: Spec file not found at {spec_file}")
        sys.exit(1)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        str(spec_file),
        "--clean",
        "--noconfirm",
    ]

    print(f"\nExecuting: {' '.join(cmd)}\n")
    proc = subprocess.run(cmd, cwd=str(root_dir))

    if proc.returncode != 0:
        print(f"\n[Build Failed] PyInstaller exited with code {proc.returncode}")
        sys.exit(proc.returncode)

    exe_path = root_dir / "dist" / "aegis.exe"
    if not exe_path.exists():
        exe_path = root_dir / "dist" / "aegis"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print("\n=================================================================")
        print("   BUILD SUCCEEDED!")
        print("=================================================================")
        print(f"Binary Path : {exe_path}")
        print(f"Binary Size : {size_mb:.2f} MB")
        print("Run with    : .\\dist\\aegis.exe --help")
        print("=================================================================\n")
    else:
        print(f"\n[Warning] Executable not found at expected path: {exe_path}")


if __name__ == "__main__":
    build()

