#!/usr/bin/env python3
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
APP_ENTRY = ROOT_DIR / "app.py"
APP_NAME = "NarrativeAI"
OPTIONAL_HIDDEN_IMPORTS = ("pysqlcipher3.dbapi2", "sqlcipher3.dbapi2")


def _data_separator():
    return ";" if os.name == "nt" else ":"


def _data_arg(source, destination):
    return f"{source}{_data_separator()}{destination}"


def _required_path(path):
    if not path.exists():
        raise FileNotFoundError(f"Required distribution asset is missing: {path}")
    return path


def _module_available(module_name):
    try:
        return importlib.util.find_spec(module_name) is not None
    except ModuleNotFoundError:
        return False


def build_command():
    templates_dir = _required_path(ROOT_DIR / "templates")
    static_dir = _required_path(ROOT_DIR / "static")
    sample_csv = _required_path(ROOT_DIR / "dummy_marketing_data.csv")

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        APP_NAME,
        "--add-data",
        _data_arg(templates_dir, "templates"),
        "--add-data",
        _data_arg(static_dir, "static"),
        "--add-data",
        _data_arg(sample_csv, "."),
    ]

    for module_name in OPTIONAL_HIDDEN_IMPORTS:
        if _module_available(module_name):
            command.extend(["--hidden-import", module_name])

    command.append(str(APP_ENTRY))
    return command


def main():
    try:
        import PyInstaller  # noqa: F401
    except ImportError as exc:
        raise SystemExit("PyInstaller is not installed. Run: venv/bin/python -m pip install -r requirements.txt") from exc

    command = build_command()
    print("Building NarrativeAI standalone app...")
    print(" ".join(str(part) for part in command))
    subprocess.run(command, cwd=ROOT_DIR, check=True)
    print(f"Build complete. Open the standalone artifact in {ROOT_DIR / 'dist'}.")


if __name__ == "__main__":
    main()
