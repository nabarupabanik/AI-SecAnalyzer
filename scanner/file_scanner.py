"""
Sprint 1 — File Scanner
Walks the project directory recursively, collecting file metadata and content.
"""
import os
from pathlib import Path
from typing import Generator, Tuple

from .file_detector import detect_file_type, is_binary
from .models import FileModel

# Directories to always skip (version control, dependencies, caches, etc.)
SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".pytest_cache",
    ".venv", "venv", "env", ".env",
    "dist", "build", "target",
    ".idea", ".vscode",
    ".tox", ".eggs", "*.egg-info",
}

# Maximum file size to read as text (5 MB) — larger files are skipped
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


def _should_skip_dir(dir_name: str) -> bool:
    """Return True if this directory should be skipped during traversal."""
    return dir_name in SKIP_DIRS or dir_name.startswith(".")


def _read_content(file_path: str, file_size: int) -> Tuple[str | None, str | None]:
    """
    Attempt to read a file as UTF-8 text.
    Returns (content, error_message). One of them is always None.
    """
    if file_size > MAX_FILE_SIZE_BYTES:
        return None, f"File too large ({file_size / 1024 / 1024:.1f} MB) — skipped"

    try:
        with open(file_path, "r", encoding="utf-8", errors="strict") as f:
            return f.read(), None
    except UnicodeDecodeError:
        try:
            with open(file_path, "r", encoding="latin-1") as f:
                return f.read(), None
        except Exception as e:
            return None, f"Encoding error: {e}"
    except PermissionError:
        return None, "Permission denied"
    except Exception as e:
        return None, str(e)


def scan_directory(project_path: str) -> Generator[FileModel, None, None]:
    """
    Walk the project directory recursively and yield a FileModel for each file.

    Skips:
    - Hidden / dependency directories (see SKIP_DIRS)
    - Binary files (content is left as None with a note)
    """
    root_path = Path(project_path).resolve()

    for dirpath, dirnames, filenames in os.walk(str(root_path)):
        # Prune unwanted directories IN-PLACE so os.walk won't descend into them
        dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
        dirnames.sort()  # deterministic ordering

        for filename in sorted(filenames):
            abs_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(abs_path, str(root_path))
            # Normalise to forward slashes for cross-platform consistency
            rel_path = rel_path.replace(os.sep, "/")

            try:
                st = os.stat(abs_path)
                file_size = int(st.st_size)
                mtime_ns = int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000)))
            except OSError:
                file_size = 0
                mtime_ns = 0

            file_type = detect_file_type(filename)
            binary = is_binary(filename)

            if binary:
                content, error = None, "Binary file — content not loaded"
            else:
                content, error = _read_content(abs_path, file_size)

            yield FileModel(
                file_name=filename,
                file_path=rel_path,
                file_type=file_type,
                extension=Path(filename).suffix.lower(),
                file_size=file_size,
                mtime_ns=mtime_ns,
                content=content,
                read_error=error,
            )


def build_folder_tree(project_path: str) -> list[str]:
    """
    Build a visual tree representation of the project directory.

    Returns a list of strings (one per line) ready to be printed.
    Example:
        project/
        ├── app.py
        ├── login.py
        └── utils/
            └── helper.py
    """
    root = Path(project_path).resolve()
    lines: list[str] = [f"{root.name}/"]

    def _walk(directory: Path, prefix: str = "") -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
        except PermissionError:
            return

        entries = [e for e in entries if not _should_skip_dir(e.name)]
        count = len(entries)

        for idx, entry in enumerate(entries):
            connector = "└── " if idx == count - 1 else "├── "
            extension = "/" if entry.is_dir() else ""
            lines.append(f"{prefix}{connector}{entry.name}{extension}")

            if entry.is_dir():
                extender = "    " if idx == count - 1 else "│   "
                _walk(entry, prefix + extender)

    _walk(root)
    return lines
