"""Build LogLens for distribution: icon + version resource → PyInstaller folder → portable zip → installer.

Usage (from the project root)::

    .venv\\Scripts\\python.exe tools\\build.py            # everything that the machine has tools for
    .venv\\Scripts\\python.exe tools\\build.py --no-installer

Intermediate outputs in ``dist/``: ``LogLens/`` (runnable folder), ``LogLens-<ver>-portable.zip``, the unsigned MSI and,
when Inno Setup 6 is installed, ``LogLens-<ver>-setup.exe``. The MSI (WiX 5, restored as a local dotnet tool from
``dotnet-tools.json``; needs the .NET SDK) is signed with ``tools/signing.ps1`` when a certificate exists
(``--require-signature`` makes that mandatory), and ONLY the publishable files are copied to ``dist/release/``:
the signed ``LogLens-<ver>.msi`` plus the README. That folder is what the GitHub release uploads.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from pathlib import Path
from xml.sax.saxutils import quoteattr

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
DIST = ROOT / "dist"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)
ISCC_CANDIDATES = (
    Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Inno Setup 6" / "ISCC.exe",
    Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Inno Setup 6" / "ISCC.exe",
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
)
WIX_VERSION = "5.0.2"  # keep in sync with dotnet-tools.json
RELEASE = DIST / "release"
log = logging.getLogger("build")


def version() -> str:
    sys.path.insert(0, str(ROOT))
    from loglens import __version__

    if not re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,4}", __version__):
        # MSI compares only major.minor.build (<=255.255.65535); a suffix like "-beta" or a 4th field is ignored/invalid
        raise SystemExit(f"loglens.__version__ {__version__!r} must be x.y.z (major<=255, minor<=255, patch<=65535)")
    return __version__


def make_icon(target: Path) -> None:
    """Multi-size .ico (PNG-compressed entries) rendered from the app's SVG logo."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    from PySide6.QtGui import QGuiApplication

    from loglens.ui.icons import logo_pixmap

    _app = QGuiApplication.instance() or QGuiApplication([])
    images = []
    for size in ICON_SIZES:
        data = QByteArray()
        buffer = QBuffer(data)
        buffer.open(QIODevice.OpenModeFlag.WriteOnly)
        logo_pixmap(size).save(buffer, "PNG")
        images.append((size, bytes(data.data())))
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries, blobs = b"", b""
    for size, png in images:
        dim = 0 if size >= 256 else size  # 0 means 256 in the ICO format
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    target.write_bytes(header + entries + blobs)


def write_version_info(target: Path, ver: str) -> None:
    parts = [int(p) for p in ver.split(".")[:3]] + [0]
    numbers = ", ".join(str(p) for p in [*parts, 0, 0, 0, 0][:4])
    target.write_text(
        f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({numbers}), prodvers=({numbers}), mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'LogLens'),
      StringStruct('FileDescription', 'LogLens log viewer and analyzer'),
      StringStruct('FileVersion', '{ver}'),
      StringStruct('InternalName', 'LogLens'),
      StringStruct('OriginalFilename', 'LogLens.exe'),
      StringStruct('ProductName', 'LogLens'),
      StringStruct('ProductVersion', '{ver}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""",
        encoding="utf-8",
    )


def run_pyinstaller() -> Path:
    command = [
        sys.executable, "-m", "PyInstaller", str(ROOT / "packaging" / "loglens.spec"),
        "--noconfirm", "--clean", "--distpath", str(DIST), "--workpath", str(BUILD / "pyinstaller"),
    ]  # fmt: skip
    subprocess.run(command, check=True, cwd=ROOT)
    return DIST / "LogLens"


def sign(path: Path, *, required: bool) -> bool:
    """Sign with tools/signing.ps1 (signtool + the local certificate). Returns False when it was skipped."""
    script = ROOT / "tools" / "signing.ps1"
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        if required:
            raise SystemExit("PowerShell not found - cannot sign")
        return False
    command = [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-Sign", str(path)]
    if subprocess.run(command, cwd=ROOT, check=False).returncode == 0:
        return True
    if required:
        raise SystemExit(f"Signing {path.name} failed (run tools/signing.ps1 -Setup once, or see the message above)")
    log.warning("%s left UNSIGNED (run: powershell -File tools/signing.ps1 -Setup -Trust)", path.name)
    return False


def publish_release_folder(msi: Path, ver: str) -> Path:
    """dist/release/ holds exactly what is uploaded to a GitHub release - nothing intermediate."""
    shutil.rmtree(RELEASE, ignore_errors=True)
    RELEASE.mkdir(parents=True)
    shutil.copy2(msi, RELEASE / msi.name)
    if (ROOT / "README.md").is_file():
        shutil.copy2(ROOT / "README.md", RELEASE / "README.md")
    return RELEASE


def make_zip(folder: Path, ver: str) -> Path:
    target = DIST / f"LogLens-{ver}-portable.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                archive.write(path, Path("LogLens") / path.relative_to(folder))
    return target


def make_installer(ver: str) -> Path | None:
    iscc = shutil.which("ISCC") or next((str(p) for p in ISCC_CANDIDATES if p.is_file()), None)
    if iscc is None:
        log.warning("Inno Setup 6 not found — skipping the installer (https://jrsoftware.org/isdl.php)")
        return None
    subprocess.run([iscc, f"/DAppVersion={ver}", str(ROOT / "packaging" / "installer.iss")], check=True)
    return DIST / f"LogLens-{ver}-setup.exe"


def write_wix_files(folder: Path, target: Path) -> int:
    """WiX fragment with one component per file of the PyInstaller folder (ComponentGroup "AppFiles")."""
    directories: dict[Path, str] = {Path(): "INSTALLFOLDER"}
    tree: dict[Path, list[Path]] = {}
    files = sorted(p for p in folder.rglob("*") if p.is_file())
    for path in files:
        relative = path.relative_to(folder).parent
        for depth in range(1, len(relative.parts) + 1):
            part = Path(*relative.parts[:depth])
            if part not in directories:
                directories[part] = "BINFOLDER" if part == Path("bin") else f"d{len(directories)}"
                tree.setdefault(part.parent, []).append(part)

    def directory_xml(parent: Path, indent: str) -> list[str]:
        out = []
        for child in sorted(tree.get(parent, [])):
            out.append(f"{indent}<Directory Id={quoteattr(directories[child])} Name={quoteattr(child.name)}>")
            out += directory_xml(child, indent + "  ")
            out.append(f"{indent}</Directory>")
        return out

    lines = ['<?xml version="1.0" encoding="utf-8"?>', '<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">',
             "  <Fragment>", '    <DirectoryRef Id="INSTALLFOLDER">']  # fmt: skip
    lines += directory_xml(Path(), "      ")
    lines += ["    </DirectoryRef>", '    <ComponentGroup Id="AppFiles">']
    for index, path in enumerate(files):
        directory = directories[path.relative_to(folder).parent]
        source = quoteattr(str(path))
        lines.append(f'      <Component Id="c{index}" Directory="{directory}">'
                     f'<File Id="f{index}" Source={source} KeyPath="yes" /></Component>')  # fmt: skip
    lines += ["    </ComponentGroup>", "  </Fragment>", "</Wix>"]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(files)


def make_msi(folder: Path, ver: str) -> Path | None:
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        log.warning("dotnet not found — skipping the MSI (install the .NET SDK)")
        return None
    # Install layout: bin/ (exe + runtime); nothing else is installed. The portable zip stays flat.
    stage = BUILD / "wix" / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    shutil.copytree(folder, stage / "bin")
    files = write_wix_files(stage, BUILD / "wix" / "files.wxs")
    log.info("MSI: %d files", files)
    subprocess.run([dotnet, "tool", "restore"], check=True, cwd=ROOT)
    # WixUI (the install-folder dialog) lives in an extension; -g installs it into the user-wide WiX extension cache.
    subprocess.run([dotnet, "wix", "extension", "add", "-g", f"WixToolset.UI.wixext/{WIX_VERSION}"],
                   check=True, cwd=ROOT)  # fmt: skip
    target = DIST / f"LogLens-{ver}.msi"
    command = [
        dotnet, "wix", "build", str(ROOT / "packaging" / "loglens.wxs"), str(BUILD / "wix" / "files.wxs"),
        "-ext", f"WixToolset.UI.wixext/{WIX_VERSION}", "-arch", "x64", "-pdbtype", "none",
        "-d", f"Version={ver}", "-d", f"IconPath={BUILD / 'loglens.ico'}",
        "-intermediatefolder", str(BUILD / "wix" / "obj"), "-o", str(target),
    ]  # fmt: skip
    subprocess.run(command, check=True, cwd=ROOT)
    return target


def finish_msi(msi: Path, ver: str, args: argparse.Namespace) -> None:
    if not args.no_sign:
        sign(msi, required=args.require_signature)
    log.info("MSI:             %s", msi)
    log.info("Release folder:  %s", publish_release_folder(msi, ver))


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--no-installer", action="store_true", help="stop after the portable zip")
    parser.add_argument("--require-signature", action="store_true", help="fail unless the MSI could be signed")
    parser.add_argument("--no-sign", action="store_true", help="leave the MSI unsigned")
    parser.add_argument("--msi-only", action="store_true", help="only rebuild the MSI from an existing dist folder")
    args = parser.parse_args()
    ver = version()
    BUILD.mkdir(exist_ok=True)
    DIST.mkdir(exist_ok=True)
    make_icon(BUILD / "loglens.ico")
    if args.msi_only:
        msi = make_msi(DIST / "LogLens", ver)
        if msi:
            finish_msi(msi, ver, args)
        return 0 if msi else 1
    write_version_info(BUILD / "version_info.txt", ver)
    folder = run_pyinstaller()
    log.info("Portable folder: %s", folder)
    log.info("Portable zip:    %s", make_zip(folder, ver))
    if not args.no_installer:
        msi = make_msi(folder, ver)
        if msi is not None:
            finish_msi(msi, ver, args)
        installer = make_installer(ver)
        if installer is not None:
            log.info("Installer:       %s", installer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
