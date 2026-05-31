#!/usr/bin/env python3
# zote_timestamp.py
# Run from ~/Desktop/ZOTE/
# Generates SHA256 manifest of ZOTE source tree
# then submits to OpenTimestamps for Bitcoin anchoring

import hashlib
import pathlib
import datetime
import subprocess
import json

# ── Files to include in the timestamp ────────────────────────────────────
INCLUDE = [
    "include/zote/types.hpp",
    "include/zote/engine.hpp",
    "include/zote/killchain.hpp",
    "include/zote/mitre.hpp",
    "include/zote/correlation.hpp",
    "include/zote/zote_engine.hpp",
    "src/engine.cpp",
    "src/killchain.cpp",
    "src/mitre_map.cpp",
    "src/correlation.cpp",
    "src/zote_engine.cpp",
    "tests/unit/test_engine.cpp",
    "tests/unit/test_killchain.cpp",
    "tests/unit/test_mitre.cpp",
    "tests/unit/test_correlation.cpp",
    "tests/unit/test_zote_engine.cpp",
    "examples/basic_detection.cpp",
    "examples/threat_hunting.cpp",
    "examples/campaign_analysis.cpp",
    "examples/confidence_scoring.cpp",
    "CMakeLists.txt",
    "docs/README.md",
    "docs/ROADMAP.md",
    "docs/contribution/CONTRIBUTING.md",
    "docs/licence/LICENSE",
    "docs/security/SECURITY.md",
    ".github/workflows/ci.yml",
]

# ── Build manifest ────────────────────────────────────────────────────────
manifest = {}
combined = hashlib.sha256()

for path_str in sorted(INCLUDE):
    p = pathlib.Path(path_str)
    if not p.exists():
        print(f"MISSING: {path_str}")
        continue
    data = p.read_bytes()
    file_hash = hashlib.sha256(data).hexdigest()
    manifest[path_str] = file_hash
    combined.update(file_hash.encode())
    combined.update(path_str.encode())

root_hash = combined.hexdigest()

# ── Write manifest file ───────────────────────────────────────────────────
pathlib.Path("docs").mkdir(exist_ok=True)

timestamp_str = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

manifest_data = {
    "project":    "ZOTE — zenithcpp Open Source Threat Engine",
    "version":    "0.1.0",
    "timestamp":  timestamp_str,
    "root_hash":  root_hash,
    "algorithm":  "SHA256",
    "files":      manifest,
    "file_count": len(manifest),
    "note": "Root hash is SHA256 of concatenated (sorted path + file hash) pairs."
}

manifest_path = pathlib.Path("docs/ZOTE_v0.1.0_manifest.json")
manifest_path.write_text(
    json.dumps(manifest_data, indent=2), encoding="utf-8")

print(f"OK -- manifest written: docs/ZOTE_v0.1.0_manifest.json")
print(f"     files:     {len(manifest)}")
print(f"     timestamp: {timestamp_str}")
print(f"     root hash: {root_hash}")
print("")

# ── Write the hash to a file for ots stamp ────────────────────────────────
hash_file = pathlib.Path("docs/ZOTE_v0.1.0.sha256")
hash_file.write_text(root_hash + "\n", encoding="utf-8")
print(f"OK -- hash file written: docs/ZOTE_v0.1.0.sha256")
print("")

# ── Submit to OpenTimestamps ──────────────────────────────────────────────
print("Submitting to OpenTimestamps calendars...")
print("(Bitcoin anchoring takes ~1 hour for block confirmation)")
print("")

result = subprocess.run(
    ["ots", "stamp", str(hash_file)],
    capture_output=True, text=True
)

if result.returncode == 0:
    print(result.stdout)
    ots_file = pathlib.Path("docs/ZOTE_v0.1.0.sha256.ots")
    if ots_file.exists():
        print(f"OK -- proof file: docs/ZOTE_v0.1.0.sha256.ots")
        print(f"     size: {ots_file.stat().st_size} bytes")
        print("")
        print("NEXT STEPS:")
        print("  1. Commit docs/ZOTE_v0.1.0.sha256.ots to the repo")
        print("  2. Wait ~1 hour for Bitcoin block confirmation")
        print("  3. Verify with: ots verify docs/ZOTE_v0.1.0.sha256.ots")
        print("  4. Share root hash as proof of authorship:")
        print(f"     {root_hash}")
    else:
        print("WARNING: .ots file not found — check ots output above")
else:
    print(f"ots stderr: {result.stderr}")
    print("")
    print("OpenTimestamps submission may need network access.")
    print("You can submit manually at: https://opentimestamps.org")
    print(f"Hash to submit: {root_hash}")
    print(f"Or run on your machine: ots stamp docs/ZOTE_v0.1.0.sha256")
