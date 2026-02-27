#!/usr/bin/env python3.11
"""
Replace git-based agave/sbpf dependencies with local path overrides
by appending [patch] sections to Cargo.toml.

Usage:
    python3.11 scripts/generate_local_cargo.py --agave-path /path/to/agave --sbpf-path /path/to/sbpf
"""

import argparse
import os
import re
import sys
import tomllib

CARGO_TOML = "Cargo.toml"

AGAVE_GIT_URL = "https://github.com/firedancer-io/agave"
SBPF_GIT_URL = "https://github.com/firedancer-io/sbpf"

PATCH_HEADER_AGAVE = f'[patch."{AGAVE_GIT_URL}"]'
PATCH_HEADER_SBPF = f'[patch."{SBPF_GIT_URL}"]'


def find_git_crates(cargo_path: str, git_url: str) -> list[str]:
    """Return sorted crate names whose dependency spec contains the given git URL."""
    with open(cargo_path, "rb") as f:
        data = tomllib.load(f)
    deps = data.get("dependencies", {})
    crates = []
    for name, spec in deps.items():
        if isinstance(spec, dict) and spec.get("git", "").rstrip("/") == git_url.rstrip("/"):
            crates.append(name)
    return sorted(crates)


def read_package_name(cargo_path: str) -> str:
    """Extract [package] name from a Cargo.toml file."""
    with open(cargo_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("package", {}).get("name", "")


def discover_crate_paths(root: str) -> dict:
    """Walk a local checkout and map package name -> directory path."""
    mapping = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and d != "target"]
        if "Cargo.toml" not in filenames:
            continue
        cargo_path = os.path.join(dirpath, "Cargo.toml")
        try:
            pkg_name = read_package_name(cargo_path)
            if pkg_name:
                mapping[pkg_name] = dirpath
        except Exception:
            continue
    return mapping


def strip_existing_patch_sections(text: str) -> str:
    """Remove previously generated [patch."...agave"] and [patch."...sbpf"] sections."""
    for header in (PATCH_HEADER_AGAVE, PATCH_HEADER_SBPF):
        escaped = re.escape(header)
        text = re.sub(
            rf"(?m)^{escaped}\s*\n(?:(?!\[).*\n)*",
            "",
            text,
        )
    return text.rstrip("\n") + "\n"


def build_patch_section(header: str, crates: list, path_map: dict) -> str:
    """Build the text for one [patch] section. Warns on missing crates."""
    lines = [header]
    for crate in crates:
        if crate not in path_map:
            print(f"WARNING: crate '{crate}' not found in local checkout, skipping", file=sys.stderr)
            continue
        path = os.path.abspath(path_map[crate])
        lines.append(f'{crate} = {{ path = "{path}" }}')
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Patch Cargo.toml to use local agave/sbpf checkouts")
    parser.add_argument("-a", "--agave-path", help="Path to local agave checkout")
    parser.add_argument("-s", "--sbpf-path", help="Path to local sbpf checkout")
    args = parser.parse_args()

    if not args.agave_path and not args.sbpf_path:
        parser.error("At least one of --agave-path or --sbpf-path is required")

    if not os.path.isfile(CARGO_TOML):
        sys.exit(f"ERROR: {CARGO_TOML} not found. Run this script from the repo root.")

    with open(CARGO_TOML, "r") as f:
        cargo_text = f.read()

    cargo_text = strip_existing_patch_sections(cargo_text)

    patches: list[str] = []

    if args.agave_path:
        agave_path = os.path.abspath(args.agave_path)
        if not os.path.isdir(agave_path):
            sys.exit(f"ERROR: agave path does not exist: {agave_path}")
        agave_crates = find_git_crates(CARGO_TOML, AGAVE_GIT_URL)
        if not agave_crates:
            print("WARNING: no agave git dependencies found in Cargo.toml", file=sys.stderr)
        else:
            agave_map = discover_crate_paths(agave_path)
            patches.append(build_patch_section(PATCH_HEADER_AGAVE, agave_crates, agave_map))

    if args.sbpf_path:
        sbpf_path = os.path.abspath(args.sbpf_path)
        if not os.path.isdir(sbpf_path):
            sys.exit(f"ERROR: sbpf path does not exist: {sbpf_path}")
        sbpf_crates = find_git_crates(CARGO_TOML, SBPF_GIT_URL)
        if not sbpf_crates:
            print("WARNING: no sbpf git dependencies found in Cargo.toml", file=sys.stderr)
        else:
            sbpf_map = discover_crate_paths(sbpf_path)
            patches.append(build_patch_section(PATCH_HEADER_SBPF, sbpf_crates, sbpf_map))

    if patches:
        cargo_text = cargo_text.rstrip("\n") + "\n\n" + "\n".join(patches)

    with open(CARGO_TOML, "w") as f:
        f.write(cargo_text)

    print(f"Patched {CARGO_TOML} successfully.")


if __name__ == "__main__":
    main()
