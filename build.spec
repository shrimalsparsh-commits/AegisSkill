# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification for AegisSkill standalone executable (aegis.exe)."""

from pathlib import Path
import sys
from PyInstaller.utils.hooks import collect_all

block_cipher = None

datas = []
binaries = []
hiddenimports = [
    "aegisskill",
    "aegisskill.main",
    "aegisskill.scanner",
    "aegisskill.parsers",
    "aegisskill.parsers.ast_extractor",
    "aegisskill.parsers.yaml_parser",
    "aegisskill.inference",
    "aegisskill.inference.engine",
    "aegisskill.inference.schemas",
    "typer",
    "rich",
    "pydantic",
    "yaml",
]

# Package tree-sitter, tree-sitter-python, and llama-cpp-python binaries & queries
for pkg in ["tree_sitter", "tree_sitter_python", "llama_cpp"]:
    try:
        pkg_datas, pkg_binaries, pkg_hidden = collect_all(pkg)
        datas.extend(pkg_datas)
        binaries.extend(pkg_binaries)
        hiddenimports.extend(pkg_hidden)
    except Exception as exc:
        print(f"[build.spec] Warning collecting package '{pkg}': {exc}")

# Outlines support if installed
try:
    pkg_datas, pkg_binaries, pkg_hidden = collect_all("outlines")
    datas.extend(pkg_datas)
    binaries.extend(pkg_binaries)
    hiddenimports.extend(pkg_hidden)
except Exception:
    pass

a = Analysis(
    ["aegisskill/main.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "notebook", "scipy", "pytest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="aegis",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

