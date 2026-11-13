"""
Sprint 1 — Application Model Builder
Orchestrates the scanner and assembles the final ApplicationModel.
"""
from .file_scanner import scan_directory, build_folder_tree
from .models import ApplicationModel, FileModel
from .static_dispatcher import run_static_analysis_all_files
from .behavior_analyzer import analyze_process_flow
from .tamper_analyzer import analyze_tamperability
from .risk_scoring import compute_overall_risk


def build_application_model(project_path: str, load_content: bool = True) -> ApplicationModel:
    """
    Scan *project_path* and return a fully populated ApplicationModel.

    Args:
        project_path:   Absolute or relative path to the project root directory.
        load_content:   If False, file content is not stored (saves memory for
                        very large projects — useful for folder-structure-only mode).

    Returns:
        ApplicationModel with all files, folder structure, and language stats.
    """
    model = ApplicationModel(project_path=str(project_path))

    # ── 1. Collect files ────────────────────────────────────────────────────
    language_counter: dict[str, int] = {}

    for file_model in scan_directory(project_path):
        if not load_content:
            file_model.content = None  # strip content to save memory

        model.files.append(file_model)
        model.file_count += 1
        model.total_size_bytes += file_model.file_size

        lang = file_model.file_type
        language_counter[lang] = language_counter.get(lang, 0) + 1

        if file_model.read_error and file_model.content is None:
            model.skipped_files.append(file_model.file_path)

    # ── 2. Compute language stats ────────────────────────────────────────────
    model.language_breakdown = dict(
        sorted(language_counter.items(), key=lambda kv: kv[1], reverse=True)
    )

    # Provide the top-level language list (excludes "Unknown" types)
    model.languages_detected = [
        lang for lang in model.language_breakdown
        if lang not in ("Unknown", "Binary")
    ]

    # ── 3. Build folder tree ─────────────────────────────────────────────────
    model.folder_structure = build_folder_tree(project_path)

    # ── 4. Static Vulnerability Analysis (plugin dispatcher) ──────────────────
    if load_content:
        run_static_analysis_all_files(model)

    # ── 5. Sprint 3: Process Flow + Malicious Behavior Detection ─────────────
    if load_content:
        analyze_process_flow(model)

    # ── 6. Sprint 4: Tamperability + Unified Risk Scoring ────────────────────
    if load_content:
        analyze_tamperability(model)
        compute_overall_risk(model)

    return model
