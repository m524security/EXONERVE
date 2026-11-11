"""Every blue-team tool must start when launched as a script from any cwd.

blue_team/exonerve.py launches each tool as `python <script>` in a subprocess,
so a tool that relies on pytest's rootdir being on sys.path (e.g. a bare
`from common.x import y`) passes in-process tests but crashes for real users.
This test launches each tool the way the runner does, from a foreign cwd.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_registry():
    spec = importlib.util.spec_from_file_location("exonerve_blue_cli", ROOT / "blue_team" / "exonerve.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_REG = _load_registry()


@pytest.mark.parametrize("tool", sorted(_REG.TOOLS))
def test_tool_starts_from_foreign_cwd(tool, tmp_path):
    script = _REG.tool_path(tool)
    assert script.exists(), f"registry points at a missing file: {script}"
    r = subprocess.run(
        [sys.executable, str(script), "--help"],
        capture_output=True, text=True, timeout=30, cwd=tmp_path,
    )
    assert r.returncode == 0, f"{tool} failed to start:\n{r.stderr[-400:]}"
