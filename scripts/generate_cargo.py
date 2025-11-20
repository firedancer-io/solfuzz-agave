#!/usr/bin/env -S uv run --script
# /// script
# dependencies = [
#     "tomlkit",
#     "requests",
#     "tomli-w",
# ]
# ///

import argparse
from tomlkit import parse, inline_table, table
import os
import subprocess
from pathlib import Path
import sys
import requests
import time
import random

# NOTE: this needs bumped with schema version upgrades of the protocol
# https://crates.io/crates/protosol
PROTOSOL_VERSION_TAG = "v3.0.0"

def replace_path_with_git_rev(toml_data, git_url, rev):
    """
    Recursively process the TOML data to replace path with git and rev,
    while preserving all other fields including features.
    """
    if isinstance(toml_data, dict):
        for key, value in list(toml_data.items()):
            if isinstance(value, dict):
                if "path" in value:
                    # Replace path with git and rev, preserve other fields
                    new_table = inline_table()
                    new_table["git"] = git_url
                    new_table["rev"] = rev
                    # Preserve version if present
                    if "version" in value:
                        new_table["version"] = value["version"]
                    # Preserve features as-is (don't add or modify)
                    if "features" in value:
                        new_table["features"] = value["features"]
                    toml_data[key] = new_table
                else:
                    replace_path_with_git_rev(value, git_url, rev)
            elif isinstance(value, list):
                for item in value:
                    replace_path_with_git_rev(item, git_url, rev)
    elif isinstance(toml_data, list):
        for item in toml_data:
            replace_path_with_git_rev(item, git_url, rev)

def replace_path_with_local(toml_data, local_path):
    """
    Recursively process the TOML data to replace path with local path,
    while preserving all other fields including features.
    """
    if isinstance(toml_data, dict):
        for key, value in list(toml_data.items()):
            if isinstance(value, dict):
                if "path" in value:
                    # Replace path with local path, preserve other fields
                    new_table = inline_table()
                    new_table["path"] = os.path.join(local_path, value["path"])
                    # Preserve version if present
                    if "version" in value:
                        new_table["version"] = value["version"]
                    # Preserve features as-is (don't add or modify)
                    if "features" in value:
                        new_table["features"] = value["features"]
                    toml_data[key] = new_table
                else:
                    replace_path_with_local(value, local_path)
            elif isinstance(value, list):
                for item in value:
                    replace_path_with_local(item, local_path)
    elif isinstance(toml_data, list):
        for item in toml_data:
            replace_path_with_local(item, local_path)

def flatten_workspace(toml_data):
    """
    Move keys from "workspace." level to the top level and remove specific keys.
    """
    if "workspace" in toml_data:
        workspace_data = toml_data.pop("workspace")
        # Remove members, exclude, resolver keys
        workspace_data.pop("members", None)
        workspace_data.pop("exclude", None)
        workspace_data.pop("resolver", None)
        for key, value in workspace_data.items():
            if key not in toml_data:
                toml_data[key] = value

def parse_toml_file(file_path):
    """
    Read the TOML file and return the parsed data.
    """
    with open(file_path, "r") as f:
        return parse(f.read())

def download_file(url, dest_path, timeout_seconds: int = 30, max_retries: int = 3, backoff_base: float = 0.5) -> None:
    """Download a URL to dest_path with retries, exponential backoff, and jitter.
    Retries on timeouts, connection errors, and 5xx HTTP responses.
    """
    last_err = None
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, stream=True, timeout=timeout_seconds)
            # Retry only on 5xx errors; raise for others
            if 500 <= response.status_code < 600:
                response.raise_for_status()
            response.raise_for_status()
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return
        except requests.Timeout as e:
            last_err = e
        except requests.ConnectionError as e:
            last_err = e
        except requests.HTTPError as e:
            # Only retry on 5xx
            status = getattr(e.response, "status_code", None)
            if status is not None and 500 <= status < 600:
                last_err = e
            else:
                raise

        if attempt < max_retries:
            sleep_secs = backoff_base * (2 ** (attempt - 1)) + random.uniform(0, backoff_base)
            time.sleep(sleep_secs)

    if last_err:
        raise last_err

def remove_unwanted_package_metadata(toml_data):
    """Remove unwanted fields from the top-level package metadata."""
    for key in ["authors", "repository", "homepage", "license"]:
        if key in toml_data.get("package", {}):
            del toml_data["package"][key]

def prepare_agave_manifest(toml_data, rewrite_paths_fn):
    """Apply common transformations to the Agave manifest then rewrite paths.

    - Flatten the workspace section
    - Remove unwanted package metadata
    - Apply a provided path rewrite function (local or git+rev)
    """
    flatten_workspace(toml_data)
    remove_unwanted_package_metadata(toml_data)
    rewrite_paths_fn(toml_data)

def strip_metadata(version: str) -> str:
    """Strip build metadata from a version string"""
    return version.split("+", 1)[0]

def pin_dependencies(toml_data, lockfile_path):
    """Pin all deps in Cargo.toml to exact versions from Cargo.lock"""
    try:
        import tomllib
    except ModuleNotFoundError:
        import tomli as tomllib
    import tomli_w

    with open(lockfile_path, "rb") as f:
        lock_data = tomllib.load(f)
    version_map = {pkg["name"]: pkg["version"] for pkg in lock_data.get("package", [])}

    sections = ["dependencies", "dev-dependencies", "build-dependencies"]
    pinned_names = set()

    def is_solana_crate(name: str) -> bool:
        return name.startswith(("solana-", "agave-", "spl-"))

    for section in sections:
        deps = toml_data.get(section, {})
        for dep_name, val in deps.items():
            if isinstance(val, str):
                package_name = dep_name
            elif isinstance(val, dict):
                package_name = val.get("package", dep_name)
            else:
                package_name = dep_name

            if package_name in pinned_names:
                continue
            pinned_names.add(package_name)

            # Only pin Solana-related crates; leave 3rd-party crates with their
            # semver ranges so Cargo can select non-yanked patch versions.
            if not is_solana_crate(package_name):
                continue

            # Do not override versions for local path dependencies.
            # These point at the local Agave workspace and must match
            # the workspace crate version (often a prerelease).
            if isinstance(val, dict) and "path" in val:
                continue

            # Do not override versions that are already exactly pinned in the overlay.
            # This allows solfuzz_agave.toml to override Agave's lockfile versions
            # (e.g. solana-epoch-rewards-hasher =3.0.0 to avoid solana-hash conflicts).
            def is_already_exact_pinned(v):
                if isinstance(v, str):
                    return v.strip().startswith("=")
                elif isinstance(v, dict):
                    ver = v.get("version", "")
                    return isinstance(ver, str) and ver.strip().startswith("=")
                return False

            if is_already_exact_pinned(val):
                continue

            # Fall back to the version present in the Agave lockfile if none declared
            if package_name not in version_map:
                continue

            pinned_version = strip_metadata(version_map[package_name])
            exact_version_str = f"={pinned_version}"

            def is_exact_pinned(v):
                if isinstance(v, str):
                    return v.strip() == exact_version_str
                elif isinstance(v, dict):
                    return str(v.get("version", "")).strip() == exact_version_str
                return False

            if is_exact_pinned(val):
                continue

            if isinstance(val, str):
                deps[dep_name] = exact_version_str
            elif isinstance(val, dict):
                val["version"] = exact_version_str

def main():
    global PROTOSOL_VERSION_TAG

    parser = argparse.ArgumentParser(description="Generate pinned Cargo.toml from Agave.")

    # Add flags
    parser.add_argument("--commit", "-c", help="Commit SHA in firedancer-io/agave to use")
    parser.add_argument("--agave-path", "-p", help="Path to local agave repo")
    parser.add_argument(
        "--output",
        "-o",
        default=os.path.join(os.getcwd(), "Cargo.toml"),
        help="Path to the output Cargo.toml (default: Cargo.toml in the current working directory)")
    parser.add_argument("--version", "-v", help=f"Protosol version to use (default {PROTOSOL_VERSION_TAG})")

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return 1

    if args.version:
        PROTOSOL_VERSION_TAG = args.version
        # Prepend 'v' if not already present
        if not PROTOSOL_VERSION_TAG.startswith('v'):
            PROTOSOL_VERSION_TAG = 'v' + PROTOSOL_VERSION_TAG
    print(f"Using protosol version: {PROTOSOL_VERSION_TAG}")

    if args.agave_path:
        agave_path_abs = os.path.abspath(args.agave_path)
        toml_data = parse_toml_file(os.path.join(agave_path_abs, "Cargo.toml"))
        prepare_agave_manifest(toml_data, lambda td: replace_path_with_local(td, agave_path_abs))
        lockfile_path = os.path.join(agave_path_abs, "Cargo.lock")
    else:
        base_url = f"https://raw.githubusercontent.com/firedancer-io/agave/{args.commit}"
        os.makedirs("dump", exist_ok=True)
        try:
            download_file(f"{base_url}/Cargo.toml", os.path.join("dump", "Cargo.toml"))
            download_file(f"{base_url}/Cargo.lock", os.path.join("dump", "Cargo.lock"))
        except requests.HTTPError as e:
            print(f"HTTP error while downloading Agave files: {e}")
            return 1
        except requests.RequestException as e:
            print(f"Network error while downloading Agave files: {e}")
            return 1
        toml_data = parse_toml_file("dump/Cargo.toml")
        prepare_agave_manifest(
            toml_data,
            lambda td: replace_path_with_git_rev(td, "https://github.com/firedancer-io/agave", args.commit),
        )
        lockfile_path = "dump/Cargo.lock"

    # remove unwanted deps except Solana-related ones
    # (which need to be pinned for deterministic builds)
    deps_to_remove = ["pickledb", "winreg", "once_cell"]
    for dep in deps_to_remove:
        if dep in toml_data.get("dependencies", {}):
            del toml_data["dependencies"][dep]

    for patch_to_remove in ["crossbeam-epoch",]:
        if patch_to_remove in toml_data.get("patch", {}).get("crates-io", {}):
            del toml_data["patch"]["crates-io"][patch_to_remove]

    # Add protosol dependency (deduped if already present)
    if "dependencies" not in toml_data:
        toml_data["dependencies"] = table()

    # Remove existing protosol if present to ensure we use the correct version
    if "protosol" in toml_data["dependencies"]:
        del toml_data["dependencies"]["protosol"]

    # Add the required protosol dependency
    protosol_dep = inline_table()
    protosol_dep["git"] = "https://github.com/firedancer-io/protosol"
    protosol_dep["tag"] = PROTOSOL_VERSION_TAG
    toml_data["dependencies"]["protosol"] = protosol_dep

    # add required solfuzz-agave added configurations
    solfuzz_agave_config = parse_toml_file("solfuzz_agave.toml")
    for section, values in solfuzz_agave_config.items():
        if section not in toml_data:
            toml_data[section] = table()
        elif not isinstance(toml_data[section], dict):
            continue

        # **FIXED: Check if values has items() method before calling it**
        if hasattr(values, 'items'):
            # It's a dictionary/table
            for k, v in values.items():
                # Special handling for dependencies section: merge features
                if section == "dependencies" and k in toml_data[section]:
                    existing_dep = toml_data[section][k]
                    # If both are dicts (dependency specs), merge them
                    if isinstance(existing_dep, dict) and isinstance(v, dict):
                        # Preserve path/git/version from existing
                        merged_dep = inline_table()
                        for key in ["path", "git", "rev", "version"]:
                            if key in existing_dep:
                                merged_dep[key] = existing_dep[key]
                        # Merge features from both
                        merged_features = []
                        if "features" in existing_dep:
                            merged_features.extend(existing_dep["features"])
                        if "features" in v:
                            for feat in v["features"]:
                                if feat not in merged_features:
                                    merged_features.append(feat)
                        if merged_features:
                            merged_dep["features"] = merged_features
                        toml_data[section][k] = merged_dep
                    else:
                        # Not both dicts, just use the solfuzz_agave.toml value
                        toml_data[section][k] = v
                else:
                    # Not a dependency or not present in existing, just assign
                    toml_data[section][k] = v
        else:
            # It's likely an Array of Tables or other non-dict type
            # Assign the entire values object directly
            toml_data[section] = values

    # pin deps from matched lockfile
    pin_dependencies(toml_data, lockfile_path)

    # Write the updated data to the output TOML file
    output_filepath_abs = os.path.abspath(args.output)

    with open(output_filepath_abs, "w") as f:
        f.write("# This file is auto generated. See generate_cargo.py\n")
        f.write(toml_data.as_string())

    # Generate lockfile using Cargo
    output_dir = os.path.dirname(args.output) or os.getcwd()
    try:
        subprocess.run(["cargo", "generate-lockfile"], cwd=output_dir, check=True)
        print(f"Generated Cargo.lock in {output_dir or '.'}")
    except subprocess.CalledProcessError as e:
        print(f"Error generating Cargo.lock: {e}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
