"""
Normalize champion icon paths to local static paths.

Usage:
    python3 scripts/normalize_champion_paths.py data/champion-summary.json

This rewrites `squarePortraitPath` to `/data/champion-icons/{id}.png`.
"""

import json
import sys
from pathlib import Path


def normalize(path: Path) -> None:
    data = json.loads(path.read_text())
    for item in data:
        cid = item.get("id")
        item["squarePortraitPath"] = f"/data/champion-icons/{cid}.png"
    path.write_text(json.dumps(data, separators=(",", ":")))
    print(f"Rewrote {len(data)} items in {path}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/normalize_champion_paths.py data/champion-summary.json")
        sys.exit(1)
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)
    normalize(path)


if __name__ == "__main__":
    main()
