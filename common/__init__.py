def _read_version() -> str:
    """Single source of truth: the repo-root VERSION file.

    The version was previously hardcoded here, in pyproject.toml, and in
    VERSION — three copies that could (and did) drift apart. The README states
    the version is "defined once in VERSION"; this makes that true.
    Falls back to the last-known value if the file is missing (e.g. when
    installed as a wheel without the data file).
    """
    try:
        from pathlib import Path as _Path
        return (_Path(__file__).resolve().parent.parent / "VERSION").read_text(
            encoding="utf-8").strip()
    except Exception:
        return "3.13.0"


__version__ = _read_version()
