"""
Sprint 1 — File Type Detector
Maps file extensions to human-readable language/type labels.
"""

# Mapping extension → language label
EXTENSION_MAP: dict[str, str] = {
    # Python
    ".py":    "Python",
    ".pyw":   "Python",
    # JavaScript / TypeScript
    ".js":    "JavaScript",
    ".mjs":   "JavaScript",
    ".cjs":   "JavaScript",
    ".ts":    "TypeScript",
    ".tsx":   "TypeScript",
    ".jsx":   "JavaScript",
    # Java
    ".java":  "Java",
    ".class": "Java Bytecode",
    ".jar":   "Java Archive",
    # C / C++
    ".c":     "C",
    ".h":     "C Header",
    ".cpp":   "C++",
    ".cc":    "C++",
    ".cxx":   "C++",
    ".hpp":   "C++ Header",
    # Configuration / data
    ".json":  "JSON",
    ".yaml":  "YAML",
    ".yml":   "YAML",
    ".toml":  "TOML",
    ".ini":   "INI Config",
    ".cfg":   "Config",
    ".env":   "Environment",
    ".conf":  "Config",
    # Web
    ".html":  "HTML",
    ".htm":   "HTML",
    ".css":   "CSS",
    ".scss":  "SCSS",
    ".xml":   "XML",
    # Shell / scripting
    ".sh":    "Shell Script",
    ".bash":  "Shell Script",
    ".bat":   "Batch Script",
    ".ps1":   "PowerShell",
    # PHP
    ".php":   "PHP",
    # Ruby
    ".rb":    "Ruby",
    # Go
    ".go":    "Go",
    # Rust
    ".rs":    "Rust",
    # SQL
    ".sql":   "SQL",
    # Markdown / docs
    ".md":    "Markdown",
    ".txt":   "Text",
    # Dockerfile
    ".dockerfile": "Dockerfile",
}

# Extensions that are almost certainly binary — we skip content loading
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".class", ".jar", ".pyc", ".pyo",
    ".db", ".sqlite", ".sqlite3",
}

# Special filenames without extensions
SPECIAL_FILENAMES = {
    "dockerfile": "Dockerfile",
    "makefile":   "Makefile",
    "jenkinsfile": "Jenkinsfile",
    "procfile":   "Procfile",
    ".env":       "Environment",
    ".gitignore": "Git Config",
    ".dockerignore": "Docker Config",
    "requirements.txt": "Python Requirements",
    "package.json":     "Node Config",
    "pom.xml":          "Maven Config",
    "build.gradle":     "Gradle Config",
}


def detect_file_type(file_name: str) -> str:
    """
    Determine the language / type label for a given filename.

    Priority order:
      1. Special filename match (e.g. Dockerfile)
      2. Extension match from EXTENSION_MAP
      3. 'Unknown' fallback
    """
    lower_name = file_name.lower()

    # 1. Special full-filename match
    if lower_name in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[lower_name]

    # 2. Extension-based lookup
    dot_pos = lower_name.rfind(".")
    if dot_pos != -1:
        ext = lower_name[dot_pos:]
        if ext in EXTENSION_MAP:
            return EXTENSION_MAP[ext]
        if ext in BINARY_EXTENSIONS:
            return "Binary"

    return "Unknown"


def is_binary(file_name: str) -> bool:
    """Return True if the file is likely binary and should not be read as text."""
    lower_name = file_name.lower()
    dot_pos = lower_name.rfind(".")
    if dot_pos != -1:
        return lower_name[dot_pos:] in BINARY_EXTENSIONS
    return False
