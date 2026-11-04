"""Inventory source/configuration and saved model metadata without copying request content."""
import hashlib
import json
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.check_output(["git", "ls-files"], cwd=root, text=True).splitlines()
    rows = []
    for name in tracked:
        path = root / name
        if path.is_file() and path.suffix in {".py", ".java", ".tsx", ".ts", ".toml", ".yml", ".sql", ".xml", ".conf"}:
            content = path.read_bytes()
            rows.append({"path": name, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    output = root / "research" / "source_inventory.json"
    output.write_text(json.dumps({"inventory_boundary": "git-tracked source and configuration at execution time",
                                  "files": rows}, indent=2) + "\n", encoding="utf-8")
    print(f"Inventoried {len(rows)} tracked files")


if __name__ == "__main__":
    main()
