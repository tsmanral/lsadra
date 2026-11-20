# PyInstaller spec for the self-contained lsadra-server the desktop app ships.
# Build steps are in desktop/README.md ("Build the bundled server"). The lsadra
# package is taken from this checkout (two folders up), so only the
# hash-locked requirements need installing, not the package itself.
import os
import sys

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

REPO = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
sys.path.insert(0, REPO)

hiddenimports = (
    collect_submodules("lsadra")
    + collect_submodules("uvicorn")
    + collect_submodules("sigma")
    + collect_submodules("apscheduler")
)
datas = collect_data_files("lsadra") + collect_data_files("sigma")

a = Analysis(
    ["lsadra_server_entry.py"],
    pathex=[REPO],
    hiddenimports=hiddenimports,
    datas=datas,
    excludes=["tkinter", "matplotlib", "IPython", "pytest", "shap", "torch"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="lsadra-server",
    console=True,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="lsadra-server", upx=False)
