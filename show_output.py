"""Quick demo script — shows the Sprint 1 scanner output in plain text."""
import time
from scanner import build_application_model

project = "./sample_project"
start = time.perf_counter()
model = build_application_model(project)
elapsed = time.perf_counter() - start

SEP = "=" * 62

print()
print(SEP)
print("   AI APPLICATION SECURITY ANALYZER  --  Sprint 1")
print("   Application Model Builder")
print(SEP)

print()
print(">>> APPLICATION MODEL CREATED")
print()
print(f"   Project Path   : {model.project_path}")
print(f"   Files Detected : {model.file_count}")
print(f"   Languages      : {', '.join(model.languages_detected)}")
print(f"   Total Size     : {model.total_size_bytes / 1024:.1f} KB")
print(f"   Skipped Files  : {len(model.skipped_files)}  (binary / unreadable)")
print(f"   Scan Time      : {elapsed:.3f}s")

print()
print(">>> LANGUAGE BREAKDOWN")
print()
print(f"   {'Language / Type':<25} {'Files':>5}  {'Percent':>7}")
print(f"   {'-'*25} {'-'*5}  {'-'*7}")
for lang, count in model.language_breakdown.items():
    pct = count / model.file_count * 100
    print(f"   {lang:<25} {count:>5}  {pct:>6.1f}%")

print()
print(">>> FOLDER STRUCTURE")
print()
for line in model.folder_structure:
    print("   " + line)

print()
print(">>> FILES SCANNED")
print()
print(f"   {'Type':<22}  {'Path':<30}  {'Size':>8}  Content Loaded?")
print(f"   {'-'*22}  {'-'*30}  {'-'*8}  ---------------")
for f in model.files:
    size_str = f"{f.file_size} B" if f.file_size < 1024 else f"{f.file_size/1024:.1f} KB"
    loaded = "YES" if f.content is not None else f"NO  ({f.read_error})"
    print(f"   {f.file_type:<22}  {f.file_path:<30}  {size_str:>8}  {loaded}")

print()
print(SEP)
print("   SPRINT 1 COMPLETE")
print("   ApplicationModel is ready for Sprint 2 (Vulnerability Scanning).")
print(SEP)
print()
