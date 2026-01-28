#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 <version>"
  echo "Example: $0 0.1.5"
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

version="$1"
if [[ "$version" == v* ]]; then
  version="${version#v}"
fi

if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid version: $version"
  exit 1
fi

tag="v$version"

if ! command -v git-cliff >/dev/null 2>&1; then
  echo "git-cliff is required. Install with: cargo install git-cliff"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to update Cargo.toml"
  exit 1
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash changes first."
  exit 1
fi

python3 - "$version" <<'PY'
import re
import sys
from pathlib import Path

version = sys.argv[1]
path = Path("Cargo.toml")
text = path.read_text(encoding="utf-8")
lines = text.splitlines()

workspace_crates = {
    "trojan",
    "trojan-core",
    "trojan-proto",
    "trojan-auth",
    "trojan-config",
    "trojan-metrics",
    "trojan-analytics",
    "trojan-server",
}

out = []
section = None
for line in lines:
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        section = stripped

    if section == "[workspace.package]" and re.match(r"^version\s*=", stripped):
        line = re.sub(r'version\s*=\s*"[^"]+"', f'version = "{version}"', line)

    if section == "[workspace.dependencies]":
        m = re.match(r"(\s*)([A-Za-z0-9_-]+)\s*=\s*\{(.*)\}\s*$", line)
        if m and m.group(2) in workspace_crates:
            line = re.sub(r'version\s*=\s*"[^"]+"', f'version = "{version}"', line)

    out.append(line)

path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY

git-cliff -c cliff.toml --tag "$tag" -o CHANGELOG.md

git add Cargo.toml Cargo.lock CHANGELOG.md

git commit -m "chore: release $tag"

git tag -a "$tag" -m "Release $tag"

echo "Release prepared: $tag"
echo "Next: git push origin HEAD && git push origin $tag"
echo "Next: cargo publish --workspace"