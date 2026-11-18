# PyInstaller spec for LogLens (one-folder build: fast start, and the installer ships the folder).
# Build with:  .venv\Scripts\python.exe tools\build.py   (generates the icon and version resource first)
# ruff: noqa
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
BUILD = ROOT / "build"
with_bedrock = os.environ.get("LOGLENS_WITH_BEDROCK") == "1"  # boto3 adds ~80 MB; off by default

hidden = ["win32timezone"]
hidden += collect_submodules("anthropic.lib.vertex")
hidden += collect_submodules("google.auth")
if with_bedrock:
    hidden += collect_submodules("anthropic.lib.bedrock") + ["boto3", "botocore"]

excludes = ["tkinter", "pytest", "_pytest", "mypy", "ruff", "IPython", "matplotlib", "PySide6.QtWebEngineCore",
            "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore", "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtMultimedia"]
if not with_bedrock:
    excludes += ["boto3", "botocore"]

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT)],
    datas=collect_data_files("loglens", includes=["**/*.toml"]),
    hiddenimports=hidden,
    excludes=excludes,
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="LogLens",
    icon=str(BUILD / "loglens.ico"),
    version=str(BUILD / "version_info.txt"),
    console=False,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="LogLens", upx=False)
