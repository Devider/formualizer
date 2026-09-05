#!/usr/bin/env python3
"""Bounded, nonpublishing native-wheel validation for the 0.9.0 RC."""

from __future__ import annotations

import argparse
import base64
import csv
import faulthandler
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import sysconfig
import tempfile
import zipfile
from email.parser import BytesParser
from email.policy import default
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable
import xml.etree.ElementTree as ET

CANDIDATE_SHA = "d58b69c549d4b13e53acab72770266e58d1df1e7"
CANDIDATE_TREE = "dea2ec6386ec6a53b2bb564c298763d1bd9ea666"
RELEASE_SHA256 = "d062c36072208d807670559d9b4b42f6833a1bc807a32abf4f5c8fb6c561c14f"
LOCK_SHA256 = "2d1637330d9a3dd7f4130b7d80ef84c1f24a00788a3c3f0a902bd8d1ab3ff73e"
PYPROJECT_SHA256 = "32f1a47cfb9c4c738e47b63ea0255b121612e88da3053a952a9b6e6a1b38f7ea"
PYTHON_CARGO_SHA256 = "b41c5fc283c39d68a8845a78481c2ef1de63cec6d0bc185b9a0208a32c8a620b"
MIT_SHA256 = "a2d81ebc68eed07c518dbfcd7028752f714ca8aa51378d8ff5d50a79248daafb"
APACHE_SHA256 = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
EXPECTED_REPOSITORY = "PSU3D0/formualizer"
EXPECTED_WORKFLOW_REF = (
    "PSU3D0/formualizer/.github/workflows/native-release-validation.yml@refs/heads/main"
)
SHA_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
WHEEL_RE = re.compile(
    r"formualizer-0\.9\.0-cp310-abi3-(?P<platform>[A-Za-z0-9_.]+)\.whl"
)

ROWS: dict[str, dict[str, str]] = {
    "linux-x86_64": {"family": "manylinux", "arch": "x86_64", "target": "x86_64-unknown-linux-gnu", "binary": "ELF", "libc": "glibc"},
    "linux-aarch64": {"family": "manylinux", "arch": "aarch64", "target": "aarch64-unknown-linux-gnu", "binary": "ELF", "libc": "glibc"},
    "musllinux-x86_64": {"family": "musllinux_1_2", "arch": "x86_64", "target": "x86_64-unknown-linux-musl", "binary": "ELF", "libc": "musl"},
    "musllinux-aarch64": {"family": "musllinux_1_2", "arch": "aarch64", "target": "aarch64-unknown-linux-musl", "binary": "ELF", "libc": "musl"},
    "windows-x64": {"family": "win", "arch": "x86_64", "target": "x86_64-pc-windows-msvc", "binary": "PE", "libc": "windows"},
    "macos-x86_64": {"family": "macosx", "arch": "x86_64", "target": "x86_64-apple-darwin", "binary": "Mach-O", "libc": "darwin"},
    "macos-aarch64": {"family": "macosx", "arch": "arm64", "target": "aarch64-apple-darwin", "binary": "Mach-O", "libc": "darwin"},
}
MUSL_DIGESTS = {
    "musllinux-x86_64": "sha256:621f8004ed526a5a6bf6a866fb415ad8da54d59a991e50b3b69167c3a768a616",
    "musllinux-aarch64": "sha256:4dffcd49f0b6fc6928a49915f3cd939f973bbecbdfe96e1e7926b6049bc0bad5",
}
BUILD_RUNNERS = {
    "linux-x86_64": ("Linux", "X64"), "linux-aarch64": ("Linux", "X64"),
    "musllinux-x86_64": ("Linux", "X64"), "musllinux-aarch64": ("Linux", "X64"),
    "windows-x64": ("Windows", "X64"),
    "macos-x86_64": ("macOS", "ARM64"), "macos-aarch64": ("macOS", "ARM64"),
}
BUILD_IMAGES = {
    "linux-x86_64": "quay.io/pypa/manylinux2014_x86_64:latest",
    "linux-aarch64": "ghcr.io/rust-cross/manylinux2014-cross:aarch64",
    "musllinux-x86_64": "ghcr.io/rust-cross/rust-musl-cross:x86_64-musl",
    "musllinux-aarch64": "ghcr.io/rust-cross/rust-musl-cross:aarch64-musl",
}
SMOKE_ASSERTIONS = {
    "parse-and-convert", "bounded-parser-depth", "evaluate-recalculate-udf",
    "inspection-pagination-trace-stamp", "xlsx-calamine-umya",
    "native-exports-host-default",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_sha(value: str, label: str) -> str:
    if SHA_RE.fullmatch(value) is None:
        fail(f"{label} must be exactly 40 lowercase hexadecimal characters")
    return value


def run(argv: list[str], *, cwd: Path | None = None, timeout: int = 60,
        env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        fail(f"command timed out after {timeout}s: {argv!r}\n{exc.stdout or ''}")
    if result.returncode != 0:
        fail(f"command failed ({result.returncode}): {argv!r}\n{result.stdout}")
    return result


def run_logged(argv: list[str], log_path: Path, *, cwd: Path, timeout: int,
               env: dict[str, str]) -> tuple[int | None, bool]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as stream:
        stream.write("argv=" + json.dumps(argv) + "\n")
        stream.flush()
        try:
            result = subprocess.run(
                argv, cwd=cwd, env=env, text=True, stdout=stream,
                stderr=subprocess.STDOUT, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            stream.write(f"\nTIMEOUT after {timeout}s\n")
            return None, True
        stream.write(f"\nreturncode={result.returncode}\n")
        return result.returncode, False


def git_output(root: Path, *args: str) -> str:
    return run(["git", "-C", str(root), *args]).stdout.strip()


def verify_checkout(root: Path, expected_sha: str, expected_tree: str | None = None) -> None:
    require_sha(expected_sha, "expected checkout SHA")
    actual = git_output(root, "rev-parse", "HEAD")
    if actual != expected_sha:
        fail(f"checkout mismatch: {actual} != {expected_sha}")
    if expected_tree is not None:
        actual_tree = git_output(root, "rev-parse", "HEAD^{tree}")
        if actual_tree != expected_tree:
            fail(f"candidate tree mismatch: {actual_tree} != {expected_tree}")
    run(["git", "-C", str(root), "diff", "--quiet"])
    run(["git", "-C", str(root), "diff", "--cached", "--quiet"])


def verify_candidate(root: Path) -> None:
    verify_checkout(root, CANDIDATE_SHA, CANDIDATE_TREE)
    fixed = {
        ".github/workflows/release.yml": RELEASE_SHA256,
        "Cargo.lock": LOCK_SHA256,
        "bindings/python/pyproject.toml": PYPROJECT_SHA256,
        "bindings/python/Cargo.toml": PYTHON_CARGO_SHA256,
    }
    for rel, expected in fixed.items():
        actual = sha256_file(root / rel)
        if actual != expected:
            fail(f"candidate file changed: {rel}: {actual} != {expected}")
    pyproject = (root / "bindings/python/pyproject.toml").read_text(encoding="utf-8")
    cargo = (root / "bindings/python/Cargo.toml").read_text(encoding="utf-8")
    if not re.search(r'(?m)^version = "0\.9\.0"$', pyproject):
        fail("Python project version is not 0.9.0")
    if 'requires-python = ">=3.10"' not in pyproject:
        fail("Python minimum version changed")
    if 'features = ["pyo3/extension-module", "pyo3/abi3-py310"]' not in pyproject:
        fail("maturin feature contract changed")
    required_features = '["eval", "workbook", "sheetport", "parse", "calamine", "umya", "system-clock"]'
    if required_features not in cargo:
        fail("native binding feature contract changed")


def parse_narrow_cargo_config(text: str, path: Path) -> list[dict[str, str]]:
    """Parse only the exact-target Cargo settings reviewed by this validator."""
    section: str | None = None
    seen: set[tuple[str, str]] = set()
    settings: list[dict[str, str]] = []
    section_re = re.compile(r"^\[target\.([a-z0-9][a-z0-9_-]*)\]$")
    value_re = re.compile(r'^"([^"\\\r\n]+)"$')
    flags_re = re.compile(r'^(?:"[^"\\\r\n]*"|\[(?:\s*"[^"\\\r\n]*"\s*,?)*\])$')
    for number, original in enumerate(text.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        if "\\" in line or "{" in line or "}" in line or ";" in line:
            fail(f"unsupported Cargo config syntax: {path}:{number}")
        if line.startswith("["):
            match = section_re.fullmatch(line)
            if match is None:
                fail(f"unsupported Cargo config section: {path}:{number}")
            section = match.group(1)
            continue
        if section is None or "=" not in line:
            fail(f"unsupported Cargo config record: {path}:{number}")
        key, raw_value = (part.strip() for part in line.split("=", 1))
        if key not in {"linker", "runner", "rustflags"}:
            fail(f"unsupported Cargo target key: {path}:{number}:{key}")
        identity = (section, key)
        if identity in seen:
            fail(f"duplicate Cargo target key: {path}:{number}:{key}")
        seen.add(identity)
        match = value_re.fullmatch(raw_value) if key != "rustflags" else flags_re.fullmatch(raw_value)
        if match is None:
            fail(f"unsupported Cargo target value: {path}:{number}:{key}")
        value = match.group(1) if key != "rustflags" else raw_value
        settings.append({"target": section, "key": key, "value": value})
    return settings


def effective_config_evidence(candidate: Path) -> list[dict[str, Any]]:
    candidate = candidate.resolve()
    paths: list[Path] = []
    current = candidate
    while True:
        found = [current / ".cargo" / name for name in ("config", "config.toml") if (current / ".cargo" / name).is_file()]
        if len(found) > 1:
            fail(f"ambiguous Cargo config/config.toml pair: {current / '.cargo'}")
        paths.extend(found)
        if current.parent == current:
            break
        current = current.parent
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve()
    cargo_home_paths = [cargo_home / name for name in ("config", "config.toml") if (cargo_home / name).is_file()]
    if len(cargo_home_paths) > 1:
        fail(f"ambiguous Cargo config/config.toml pair: {cargo_home}")
    paths.extend(path for path in cargo_home_paths if path not in paths)
    evidence: list[dict[str, Any]] = []
    for path in paths:
        parsed = parse_narrow_cargo_config(path.read_text(encoding="utf-8"), path)
        evidence.append({
            "path": str(path), "sha256": sha256_file(path),
            "reviewed_cross_settings": json.dumps(parsed, separators=(",", ":"), sort_keys=True),
            "target_settings": parsed,
        })
    return evidence


def reject_toolchain_overrides(candidate: Path, target: str | None = None) -> list[dict[str, Any]]:
    forbidden = [
        "CARGO", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR",
    ]
    present = [key for key in forbidden if os.environ.get(key)]
    if present:
        fail("forbidden compiler/build overrides: " + ", ".join(present))
    build_target = os.environ.get("CARGO_BUILD_TARGET", "")
    if build_target and (target is None or build_target != target):
        fail(f"CARGO_BUILD_TARGET does not match the resolved target: {build_target!r}")
    value = os.environ.get("RUSTUP_TOOLCHAIN")
    if value not in (None, "", "1.93.0"):
        fail(f"unexpected RUSTUP_TOOLCHAIN: {value}")
    return effective_config_evidence(candidate)


def command_preflight(args: argparse.Namespace) -> None:
    candidate_sha = require_sha(args.candidate_sha, "candidate_sha")
    workflow_sha = require_sha(args.workflow_sha, "workflow_sha")
    expected_workflow_sha = require_sha(args.expected_workflow_sha, "expected_workflow_sha")
    if candidate_sha != CANDIDATE_SHA:
        fail("this validator is frozen to the d58 candidate")
    checks = {
        "event_name": (args.event_name, "workflow_dispatch"),
        "ref": (args.ref, "refs/heads/main"),
        "repository": (args.repository, EXPECTED_REPOSITORY),
        "workflow_ref": (args.workflow_ref, EXPECTED_WORKFLOW_REF),
        "workflow_sha": (workflow_sha, expected_workflow_sha),
    }
    for label, (actual, expected) in checks.items():
        if actual != expected:
            fail(f"{label} mismatch: {actual!r} != {expected!r}")
    driver = Path(args.driver).resolve()
    candidate = Path(args.candidate).resolve()
    verify_checkout(driver, workflow_sha)
    verify_candidate(candidate)
    reject_toolchain_overrides(candidate)
    print(json.dumps({
        "kind": "preflight", "status": "pass", "candidate_sha": candidate_sha,
        "candidate_tree": CANDIDATE_TREE, "workflow_sha": workflow_sha,
        "release_recipe_hash": RELEASE_SHA256, "cargo_lock_hash": LOCK_SHA256,
    }, sort_keys=True))


def command_verify_source(args: argparse.Namespace) -> None:
    candidate = Path(args.candidate).resolve()
    verify_candidate(candidate)
    reject_toolchain_overrides(candidate)
    print("candidate tracked source is clean and frozen")


def command_verify_driver(args: argparse.Namespace) -> None:
    verify_checkout(Path(args.driver).resolve(), require_sha(args.workflow_sha, "workflow_sha"))
    print("validation driver is the exact workflow commit")


def configured_linker(configs: list[dict[str, Any]], target: str) -> tuple[str | None, str | None]:
    env_name = "CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER"
    env_value = os.environ.get(env_name)
    if env_value:
        return env_value, env_name
    for item in configs:
        for setting in item["target_settings"]:
            if setting["target"] == target and setting["key"] == "linker":
                return setting["value"], item["path"]
    return None, None


def command_probe(argv: list[str], cwd: Path) -> dict[str, Any]:
    result = subprocess.run(
        argv, cwd=cwd, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=30, check=False,
    )
    return {"argv": argv, "returncode": result.returncode, "output": result.stdout}


def tiny_link_args(candidate: Path, target: str, linker: str | None = None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="native-linker-proof-") as tmp:
        output = Path(tmp) / ("probe.exe" if target.endswith("windows-msvc") else "probe")
        argv = ["rustc", "--crate-name", "native_validator_linker_probe", "--target", target]
        if linker is not None:
            argv.extend(["-C", "linker=" + linker])
        argv.extend(["--print", "link-args", "-o", str(output), "-"])
        result = subprocess.run(
            argv,
            cwd=candidate, input="fn main() {}\n", text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=60, check=False,
        )
    recorded_argv = ["rustc", "--target", target]
    if linker is not None:
        recorded_argv.extend(["-C", "linker=" + linker])
    recorded_argv.extend(["--print", "link-args", "<stdin>"])
    probe = {"argv": recorded_argv,
             "returncode": result.returncode, "output": result.stdout}
    if result.returncode != 0 or not result.stdout.strip():
        fail(f"tiny rustc linker probe failed for {target}:\n{result.stdout}")
    return probe


def require_recognized_tool_probe(probe: dict[str, Any], family: str, label: str) -> None:
    output = str(probe.get("output", ""))
    if probe.get("returncode") != 0:
        fail(f"{label} probe returned nonzero status")
    patterns = {
        "msvc-link": r"(?i)Microsoft.*Incremental Linker",
        "msvc-cl": r"(?i)Microsoft.*C/C\+\+.*Compiler",
        "apple-clang": r"Apple clang version",
        "gnu-driver": r"(?im)^(?:[A-Za-z0-9_+./-]*(?:cc|gcc)) \([^)]+\) \d|^(?:Apple )?clang version \d",
    }
    if not output.strip() or re.search(patterns[family], output) is None:
        fail(f"{label} probe has no recognized {family} banner")


def windows_msvc_tools(candidate: Path) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    program_files = os.environ.get("ProgramFiles(x86)")
    if not program_files:
        fail("ProgramFiles(x86) is unavailable for MSVC discovery")
    vswhere = Path(program_files) / "Microsoft Visual Studio/Installer/vswhere.exe"
    installation = run([
        str(vswhere), "-latest", "-products", "*", "-requires",
        "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath",
    ], cwd=candidate).stdout.strip()
    version_file = Path(installation) / "VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt"
    version = version_file.read_text(encoding="utf-8").strip()
    tools = Path(installation) / "VC/Tools/MSVC" / version / "bin/Hostx64/x64"
    linker = tools / "link.exe"
    compiler = tools / "cl.exe"
    if not linker.is_file() or not compiler.is_file():
        fail("architecture-matched MSVC compiler/linker was not found")
    linker_probe = command_probe([str(linker), "/?"], candidate)
    compiler_probe = command_probe([str(compiler), "/?"], candidate)
    require_recognized_tool_probe(linker_probe, "msvc-link", "MSVC linker")
    require_recognized_tool_probe(compiler_probe, "msvc-cl", "MSVC compiler")
    return str(linker), str(compiler), linker_probe, compiler_probe


def compiler_output(candidate: Path, target: str) -> dict[str, Any]:
    candidate = candidate.resolve()
    configs = reject_toolchain_overrides(candidate, target)
    rustc = run(["rustc", "-vV"], cwd=candidate).stdout
    first = rustc.splitlines()[0] if rustc.splitlines() else ""
    if first != "rustc 1.93.0 (254b59607 2026-01-19)":
        fail(f"effective rustc mismatch: {first!r}")
    installed_targets = run(["rustup", "target", "list", "--installed"], cwd=candidate).stdout.splitlines()
    if target not in installed_targets:
        fail(f"resolved target is not installed: {target}")
    maturin = run(["maturin", "--version"], cwd=candidate).stdout.strip()
    if maturin != "maturin 1.11.5":
        fail(f"effective maturin mismatch: {maturin}")
    configured, configured_source = configured_linker(configs, target)
    link_args_probe = tiny_link_args(candidate, target, configured)
    if os.name == "nt":
        resolved_linker, compiler_path, linker_probe, compiler_probe = windows_msvc_tools(candidate)
        linker = configured or "link.exe"
        linker_source = configured_source or "rustc-link-args+vswhere-msvc"
        if "link.exe" not in link_args_probe["output"].lower():
            fail("rustc linker probe did not select the architecture-matched MSVC linker")
    elif sys.platform == "darwin":
        resolved_linker = run(["xcrun", "--find", "clang"], cwd=candidate).stdout.strip()
        sdk_path = run(["xcrun", "--sdk", "macosx", "--show-sdk-path"], cwd=candidate).stdout.strip()
        compiler_path = resolved_linker
        linker_probe = command_probe([resolved_linker, "--version"], candidate)
        compiler_probe = command_probe([compiler_path, "--version"], candidate)
        require_recognized_tool_probe(linker_probe, "apple-clang", "Apple linker driver")
        require_recognized_tool_probe(compiler_probe, "apple-clang", "Apple compiler")
        linker = configured or "cc"
        linker_source = configured_source or "rustc-link-args+xcrun-apple-clang"
        if not sdk_path or not Path(sdk_path).is_dir():
            fail("Apple SDK discovery failed")
    else:
        linker = configured or "cc"
        linker_source = configured_source or "rustc-link-args-target-default"
        if not linker or any(char in linker for char in "\r\n"):
            fail("configured linker is not a single executable path")
        resolved_linker = shutil.which(linker)
        if resolved_linker is None:
            fail(f"resolved linker is not executable: {linker}")
        compiler_path = resolved_linker
        linker_probe = command_probe([resolved_linker, "--version"], candidate)
        compiler_probe = command_probe([compiler_path, "--version"], candidate)
        require_recognized_tool_probe(linker_probe, "gnu-driver", "linker driver")
        require_recognized_tool_probe(compiler_probe, "gnu-driver", "target C compiler")
    observed_name = Path(linker).name.lower()
    if observed_name not in link_args_probe["output"].lower():
        fail(f"rustc link-args did not contain the selected linker: {linker}")
    target_env_prefix = "CARGO_TARGET_" + target.upper().replace("-", "_")
    env_keys = (
        "CC", "CXX", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS",
        "ARCHFLAGS", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT", "RUSTUP_TOOLCHAIN",
        "CARGO_BUILD_TARGET", target_env_prefix + "_LINKER", target_env_prefix + "_RUSTFLAGS",
    )
    data: dict[str, Any] = {
        "rustc_vv": rustc,
        "cargo_version": run(["cargo", "-V"], cwd=candidate).stdout.strip(),
        "active_toolchain": run(["rustup", "show", "active-toolchain"], cwd=candidate).stdout.strip(),
        "rustc_path": run(["rustup", "which", "rustc"], cwd=candidate).stdout.strip(),
        "installed_targets": installed_targets,
        "maturin_version": maturin,
        "target": target,
        "target_libdir": run(["rustc", "--print", "target-libdir", "--target", target], cwd=candidate).stdout.strip(),
        "linker": linker,
        "linker_source": linker_source,
        "linker_path": resolved_linker,
        "link_args_probe": link_args_probe,
        "linker_probe": linker_probe,
        "c_compiler_path": compiler_path,
        "c_compiler_probe": compiler_probe,
        "cargo_configs": configs,
        "effective_flags": {key: os.environ.get(key, "") for key in env_keys},
        "build_python": {"executable": sys.executable, "version": platform.python_version()},
    }
    return data


def command_compiler_proof(args: argparse.Namespace) -> None:
    data = compiler_output(Path(args.candidate), args.target)
    data.update({
        "kind": "compiler", "status": "pass", "build_row": args.row,
        "runner_os": args.runner_os, "runner_arch": args.runner_arch,
        "runner_image_os": args.runner_image_os,
        "runner_image_version": args.runner_image_version,
    })
    if not args.runner_image_os or not args.runner_image_version:
        fail("hosted runner image identity is missing")
    Path(args.output).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


RAW_SCALARS = (
    "format", "build_row", "target", "config_scan", "cargo_build_target", "target_rustflags",
    "rustc_version", "rustc_path", "target_libdir", "linker", "linker_path", "linker_source",
    "c_compiler_path", "maturin_version", "build_python_status", "build_python_executable",
    "build_python_version", "cc", "cxx", "cflags", "cppflags", "cxxflags", "ldflags",
    "archflags", "macosx_deployment_target", "sdkroot",
)
RAW_BLOCKS = ("rustc_vv", "link_args", "c_compiler", "linker_probe")


def parse_linux_compiler_raw(raw: str, row: str) -> tuple[dict[str, str], list[dict[str, str]], dict[str, str]]:
    lines = raw.splitlines()
    values: dict[str, str] = {}
    configs: list[dict[str, str]] = []
    config_paths: set[str] = set()
    index = 0
    for expected_key in RAW_SCALARS:
        if index >= len(lines) or "=" not in lines[index]:
            fail(f"missing or out-of-order Linux compiler field: {expected_key}")
        key, value = lines[index].split("=", 1)
        if key != expected_key or key in values:
            fail(f"duplicate, malformed, or out-of-order Linux compiler field: {key}")
        values[key] = value
        index += 1
    while index < len(lines) and lines[index].startswith("cargo_config="):
        fields = lines[index].removeprefix("cargo_config=").split("|", 2)
        if len(fields) != 3 or not fields[0].startswith("/") or DIGEST_RE.fullmatch(fields[1]) is None:
            fail("malformed Cargo config evidence")
        settings = fields[2]
        if fields[0] in config_paths:
            fail("duplicate Cargo config evidence")
        config_paths.add(fields[0])
        tokens = [token for token in settings.split(";") if token]
        active_targets: set[str] = set()
        setting_keys: set[tuple[str, str]] = set()
        for token in tokens:
            section_match = re.fullmatch(r"target\.([a-z0-9][a-z0-9_-]*)", token)
            if section_match:
                active_targets.add(section_match.group(1))
                continue
            setting_match = re.fullmatch(r"target\.([a-z0-9][a-z0-9_-]*):(linker|runner|rustflags)=(.+)", token)
            if setting_match is None or setting_match.group(1) not in active_targets:
                fail("malformed reviewed Cargo config settings")
            identity = (setting_match.group(1), setting_match.group(2))
            if identity in setting_keys:
                fail("duplicate reviewed Cargo config setting")
            setting_keys.add(identity)
        if any(token in settings for token in ("\\", "{", "}")):
            fail("unsupported Cargo config evidence")
        configs.append({"path": fields[0], "sha256": fields[1], "reviewed_cross_settings": settings})
        index += 1
    blocks: dict[str, str] = {}
    for name in RAW_BLOCKS:
        begin, end = name + "_begin", name + "_end"
        if index >= len(lines) or lines[index] != begin:
            fail(f"missing or out-of-order Linux compiler block: {begin}")
        index += 1
        content: list[str] = []
        while index < len(lines) and lines[index] != end:
            if lines[index].endswith("_begin") or lines[index].endswith("_end"):
                fail(f"nested or malformed Linux compiler block: {lines[index]}")
            content.append(lines[index])
            index += 1
        if index >= len(lines) or not content or not any(line.strip() for line in content):
            fail(f"empty or unterminated Linux compiler block: {name}")
        blocks[name] = "\n".join(content) + "\n"
        index += 1
    if index != len(lines):
        fail(f"unexpected Linux compiler proof record: {lines[index]!r}")
    target = ROWS[row]["target"]
    expected = {
        "format": "native-compiler-proof-v2", "build_row": row, "target": target,
        "config_scan": "pass", "rustc_version": "rustc 1.93.0 (254b59607 2026-01-19)",
        "maturin_version": "maturin 1.11.5", "build_python_status": "not-selected-by-validator",
        "build_python_executable": "", "build_python_version": "",
    }
    if any(values.get(key) != value for key, value in expected.items()):
        fail("Linux in-container compiler proof fields are missing or mismatched")
    if values["cargo_build_target"] not in ("", target):
        fail("Linux compiler proof has a mismatched CARGO_BUILD_TARGET")
    for key in ("rustc_path", "target_libdir", "linker", "linker_path", "linker_source", "c_compiler_path"):
        if not values[key] or "placeholder" in values[key].lower() or (key.endswith("path") or key in {"rustc_path", "target_libdir"}) and not values[key].startswith("/"):
            fail(f"Linux compiler proof lacks a substantive {key}")
    if not values["rustc_path"].endswith("/rustc") or f"/rustlib/{target}/lib" not in values["target_libdir"]:
        fail("Linux rustc path/target libdir is not target-specific")
    if values["linker_path"].rsplit("/", 1)[-1] != values["linker"].rsplit("/", 1)[-1] or values["c_compiler_path"] != values["linker_path"]:
        fail("Linux target compiler/linker paths do not reconcile")
    rustc_block = blocks["rustc_vv"]
    if "rustc 1.93.0 (254b59607 2026-01-19)" not in rustc_block or "release: 1.93.0" not in rustc_block or "cargo 1.93.0" not in rustc_block or target not in rustc_block:
        fail("Linux rustc verbose block is not substantive")
    if values["linker"].rsplit("/", 1)[-1].lower() not in blocks["link_args"].lower():
        fail("Linux link-args block does not contain the selected linker")
    for name in ("c_compiler", "linker_probe"):
        require_recognized_tool_probe({"returncode": 0, "output": blocks[name]}, "gnu-driver", f"Linux {name}")
    return values, configs, blocks


def command_linux_compiler_proof(args: argparse.Namespace) -> None:
    candidate = Path(args.candidate).resolve()
    reject_toolchain_overrides(candidate)
    raw_path = Path(args.raw)
    raw = raw_path.read_text(encoding="utf-8")
    values, config_rows, blocks = parse_linux_compiler_raw(raw, args.row)
    if not args.runner_image_os or not args.runner_image_version:
        fail("hosted runner image identity is missing")
    link_args_argv = ["rustc", "--target", values["target"]]
    if values["linker_source"] != "rustc-link-args-target-default":
        link_args_argv.extend(["-C", "linker=" + values["linker_path"]])
    link_args_argv.extend(["--print", "link-args", "<stdin>"])
    data = {
        "kind": "compiler", "status": "pass", "build_row": args.row,
        "target": values["target"], "rustc_version": values["rustc_version"],
        "rustc_path": values["rustc_path"], "target_libdir": values["target_libdir"],
        "linker": values["linker"], "linker_path": values["linker_path"],
        "linker_source": values["linker_source"],
        "link_args_probe": {"argv": link_args_argv, "returncode": 0, "output": blocks["link_args"]},
        "linker_probe": {"argv": [values["linker_path"], "--version"], "returncode": 0, "output": blocks["linker_probe"]},
        "c_compiler_path": values["c_compiler_path"],
        "c_compiler_probe": {"argv": [values["c_compiler_path"], "--version"], "returncode": 0, "output": blocks["c_compiler"]},
        "maturin_version": values["maturin_version"], "cargo_configs": config_rows,
        "runner_os": args.runner_os, "runner_arch": args.runner_arch,
        "runner_image_os": args.runner_image_os,
        "runner_image_version": args.runner_image_version,
        "build_python": {"status": values["build_python_status"], "executable": "", "version": ""},
        "rustc_vv": blocks["rustc_vv"],
        "effective_flags": {key: values.get(key.lower(), "") for key in ("CC", "CXX", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "ARCHFLAGS", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT")} | {
            "CARGO_BUILD_TARGET": values["cargo_build_target"], "TARGET_RUSTFLAGS": values["target_rustflags"],
        },
        "raw_sha256": sha256_file(raw_path),
    }
    Path(args.output).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def platform_ok(row: str, tag: str) -> bool:
    spec = ROWS[row]
    family = spec["family"]
    arch = spec["arch"]
    if family == "manylinux":
        return "manylinux" in tag and "musllinux" not in tag and tag.endswith("_" + arch)
    if family == "musllinux_1_2":
        return "musllinux_1_2" in tag and tag.endswith("_" + arch)
    if family == "win":
        return tag == "win_amd64"
    if family == "macosx":
        return "macosx" in tag and tag.endswith("_" + arch) and "universal2" not in tag
    return False


def inspect_binary(data: bytes, row: str) -> dict[str, Any]:
    expected = ROWS[row]["arch"]
    if data[:4] == b"\x7fELF":
        if len(data) < 20:
            fail("truncated ELF extension")
        endian = "<" if data[5] == 1 else ">" if data[5] == 2 else ""
        if not endian:
            fail("invalid ELF byte order")
        machine = struct.unpack(endian + "H", data[18:20])[0]
        actual = {62: "x86_64", 183: "aarch64"}.get(machine, f"elf-{machine}")
        bits = {1: 32, 2: 64}.get(data[4], 0)
        kind = "ELF"
    elif data[:2] == b"MZ":
        if len(data) < 64:
            fail("truncated PE extension")
        offset = struct.unpack("<I", data[60:64])[0]
        if data[offset:offset + 4] != b"PE\0\0":
            fail("invalid PE extension")
        machine = struct.unpack("<H", data[offset + 4:offset + 6])[0]
        actual = {0x8664: "x86_64", 0xAA64: "arm64"}.get(machine, f"pe-{machine}")
        bits = 64
        kind = "PE"
    elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        endian = "<" if data[:4] == b"\xcf\xfa\xed\xfe" else ">"
        cpu = struct.unpack(endian + "I", data[4:8])[0]
        actual = {0x01000007: "x86_64", 0x0100000C: "arm64"}.get(cpu, f"macho-{cpu}")
        bits = 64
        kind = "Mach-O"
    elif data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        fail("universal/fat Mach-O is not an exact release row")
    else:
        fail("unknown native extension format")
    aliases = {"aarch64": {"aarch64", "arm64"}, "arm64": {"aarch64", "arm64"}}
    allowed = aliases.get(expected, {expected})
    if kind != ROWS[row]["binary"]:
        fail(f"native extension format mismatch: {kind} for {row}")
    if actual not in allowed or bits != 64:
        fail(f"native extension architecture mismatch: {actual}/{bits} for {row}")
    return {"format": kind, "architecture": actual, "pointer_width": bits}


def safe_zip_infos(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = archive.infolist()
    names: set[str] = set()
    destinations: set[str] = set()
    for info in infos:
        raw = info.filename
        if not raw or "\\" in raw or raw.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", raw):
            fail(f"unsafe raw ZIP member: {raw!r}")
        components = raw.split("/")
        if any(component in ("", ".", "..") for component in components):
            fail(f"noncanonical ZIP member: {raw}")
        path = PurePosixPath(raw)
        if str(path) != raw or path.is_absolute():
            fail(f"noncanonical ZIP member: {raw}")
        destination = "/".join(component.casefold() for component in components)
        if raw in names or destination in destinations:
            fail(f"duplicate/colliding ZIP member: {raw}")
        names.add(raw)
        destinations.add(destination)
        mode = (info.external_attr >> 16) & 0o170000
        if mode == 0o120000:
            fail(f"symlink ZIP member: {info.filename}")
        if info.is_dir() or mode not in (0, 0o100000):
            fail(f"non-regular ZIP member: {info.filename}")
    return infos


def one_wheel(wheelhouse: Path, row: str) -> Path:
    entries = sorted(wheelhouse.iterdir())
    files = [path for path in entries if path.is_file()]
    wheels = [path for path in files if path.suffix == ".whl"]
    if len(entries) != 1 or len(wheels) != 1:
        fail(f"wheelhouse must contain exactly one wheel, found: {[p.name for p in entries]}")
    match = WHEEL_RE.fullmatch(wheels[0].name)
    if match is None:
        fail(f"unexpected wheel filename: {wheels[0].name}")
    if row not in ROWS or not platform_ok(row, match.group("platform")):
        fail(f"wheel platform {match.group('platform')} does not match {row}")
    return wheels[0]


def audit_wheel(wheelhouse: Path, row: str, canonical_root: Path) -> dict[str, Any]:
    wheel = one_wheel(wheelhouse, row)
    canonical = {
        "LICENSE-MIT": (canonical_root / "LICENSE-MIT").read_bytes(),
        "LICENSE-APACHE": (canonical_root / "LICENSE-APACHE").read_bytes(),
    }
    if sha256_bytes(canonical["LICENSE-MIT"]) != MIT_SHA256 or sha256_bytes(canonical["LICENSE-APACHE"]) != APACHE_SHA256:
        fail("canonical candidate license bytes changed")
    with zipfile.ZipFile(wheel) as archive:
        infos = safe_zip_infos(archive)
        names = [item.filename for item in infos]
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(metadata_names) != 1 or len(wheel_names) != 1 or len(record_names) != 1:
            fail("wheel must contain exactly one METADATA, WHEEL, and RECORD")
        metadata = BytesParser(policy=default).parsebytes(archive.read(metadata_names[0]))
        required = {
            "Name": "formualizer", "Version": "0.9.0", "Requires-Python": ">=3.10",
            "License-Expression": "MIT",
        }
        for key, expected in required.items():
            if metadata.get(key) != expected:
                fail(f"METADATA {key} mismatch: {metadata.get(key)!r}")
        license_files = sorted(metadata.get_all("License-File", []))
        if license_files != ["LICENSE-APACHE", "LICENSE-MIT"]:
            fail(f"License-File declarations mismatch: {license_files}")
        for license_name, expected_bytes in canonical.items():
            members = [name for name in names if PurePosixPath(name).name == license_name]
            if len(members) != 1 or archive.read(members[0]) != expected_bytes:
                fail(f"wheel {license_name} is absent, duplicated, or noncanonical")
        record_rows = list(csv.reader(archive.read(record_names[0]).decode("utf-8").splitlines()))
        if len(record_rows) != len(names):
            fail("RECORD does not enumerate the complete wheel")
        recorded: set[str] = set()
        for fields in record_rows:
            if len(fields) != 3 or fields[0] in recorded or fields[0] not in names:
                fail(f"invalid RECORD row: {fields}")
            recorded.add(fields[0])
            if fields[0] == record_names[0]:
                if fields[1:] != ["", ""]:
                    fail("RECORD self-row must be unhashed")
                continue
            data = archive.read(fields[0])
            if fields[2] != str(len(data)):
                fail(f"RECORD size mismatch: {fields[0]}")
            if not fields[1].startswith("sha256="):
                fail(f"RECORD hash algorithm mismatch: {fields[0]}")
            encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
            if fields[1] != "sha256=" + encoded:
                fail(f"RECORD hash mismatch: {fields[0]}")
        required_suffixes = ("/__init__.py", "/__init__.pyi", "/formualizer_py.pyi", "/py.typed")
        for suffix in required_suffixes:
            if not any(name.endswith(suffix) for name in names):
                fail(f"wheel missing required payload: {suffix}")
        native = [name for name in names if "/formualizer_py." in name and name.endswith((".so", ".pyd", ".dylib"))]
        if len(native) != 1:
            fail(f"wheel must contain one native extension, found {native}")
        wrapper = [name for name in names if name.endswith("formualizer/__init__.py")]
        if len(wrapper) != 1:
            fail("wheel wrapper module inventory mismatch")
        wheel_text = archive.read(wheel_names[0]).decode("utf-8")
        tags = [line[5:] for line in wheel_text.splitlines() if line.startswith("Tag: ")]
        if not tags or any(not tag.startswith("cp310-abi3-") for tag in tags):
            fail(f"unexpected WHEEL tags: {tags}")
        if any(not platform_ok(row, tag.rsplit("-", 1)[-1]) for tag in tags):
            fail(f"WHEEL tag platform does not match {row}: {tags}")
        native_bytes = archive.read(native[0])
        binary = inspect_binary(native_bytes, row)
        return {
            "kind": "build", "status": "pass", "build_row": row,
            "candidate_sha": CANDIDATE_SHA, "candidate_tree": CANDIDATE_TREE,
            "release_recipe_hash": RELEASE_SHA256, "cargo_lock_hash": LOCK_SHA256,
            "resolved_target": ROWS[row]["target"], "wheel_filename": wheel.name,
            "wheel_sha256": sha256_file(wheel), "wheel_size": wheel.stat().st_size,
            "wheel_tags": tags, "native_member": native[0],
            "native_sha256": sha256_bytes(native_bytes), "wrapper_member": wrapper[0],
            "wrapper_sha256": sha256_bytes(archive.read(wrapper[0])), "binary": binary,
            "record_entries": len(record_rows), "license_status": "canonical",
        }


def command_audit_wheel(args: argparse.Namespace) -> None:
    verify_candidate(Path(args.candidate).resolve())
    report = audit_wheel(Path(args.wheelhouse).resolve(), args.row, Path(args.candidate).resolve())
    evidence_path = Path(args.compiler_evidence)
    if not evidence_path.is_file():
        fail("compiler evidence is missing")
    try:
        compiler = json.loads(evidence_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"compiler evidence is not structured JSON: {exc}")
    rustc_text = str(compiler.get("rustc_vv", compiler.get("rustc_version", "")))
    if "rustc 1.93.0 (254b59607 2026-01-19)" not in rustc_text:
        fail("compiler evidence does not prove Rust 1.93.0")
    if compiler.get("maturin_version") != "maturin 1.11.5":
        fail("compiler evidence does not prove maturin 1.11.5")
    if compiler.get("target") != ROWS[args.row]["target"] or compiler.get("build_row") != args.row:
        fail("compiler evidence does not contain the resolved Rust target/build row")
    report["compiler_evidence_sha256"] = sha256_file(evidence_path)
    report["workflow_sha"] = require_sha(args.workflow_sha, "workflow_sha")
    report["action_commit"] = args.action_commit
    report["runner_image"] = args.runner_image
    report["runner_arch"] = args.runner_arch
    report["run_id"] = args.run_id
    report["run_attempt"] = args.run_attempt
    if args.native_output:
        native_output = Path(args.native_output)
        native_output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(one_wheel(Path(args.wheelhouse).resolve(), args.row)) as archive:
            native_output.write_bytes(archive.read(report["native_member"]))
        if sha256_file(native_output) != report["native_sha256"]:
            fail("native inspection copy hash mismatch")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def isolated_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        env.pop(key, None)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    return env


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def stage_tests(candidate: Path, staging: Path) -> tuple[Path, Path]:
    source = candidate / "bindings/python"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    shutil.copytree(source / "tests", staging / "tests")
    shutil.copy2(source / "pyproject.toml", staging / "pyproject.toml")
    shutil.copy2(candidate / "LICENSE-MIT", staging / "LICENSE-MIT")
    shutil.copy2(candidate / "LICENSE-APACHE", staging / "LICENSE-APACHE")
    helper = staging / "native-wheel-validation.py"
    shutil.copy2(Path(__file__).resolve(), helper)
    if (staging / "formualizer").exists() or any(staging.rglob("Cargo.toml")):
        fail("test staging copied package or Cargo source")
    for src in (source / "tests").rglob("*"):
        if src.is_file():
            dst = staging / "tests" / src.relative_to(source / "tests")
            if sha256_file(src) != sha256_file(dst):
                fail(f"staged test hash mismatch: {src}")
    return helper, staging / "pyproject.toml"


def normalize_machine(value: str) -> str:
    lowered = value.lower()
    aliases = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}
    if lowered not in aliases:
        fail(f"unknown machine architecture: {value}")
    return aliases[lowered]


def require_installed_path(path: Path, site_roots: Iterable[Path], forbidden: Iterable[Path], label: str) -> None:
    resolved = path.resolve()
    roots = [root.resolve() for root in site_roots]
    if not any(root == resolved or root in resolved.parents for root in roots):
        fail(f"{label} does not resolve inside this interpreter's site-packages")
    for root in forbidden:
        resolved_root = root.resolve()
        if resolved_root == resolved or resolved_root in resolved.parents:
            fail(f"{label} resolved from a forbidden source path")


def command_installed_smoke(args: argparse.Namespace) -> None:
    faulthandler.enable()
    faulthandler.dump_traceback_later(120, exit=True)
    row = args.row
    audit = audit_wheel(Path(args.wheelhouse).resolve(), row, Path(args.licenses).resolve())
    expected_python = tuple(int(piece) for piece in args.python_version.split("."))
    if sys.implementation.name != "cpython" or sys.version_info[:2] != expected_python:
        fail(f"interpreter mismatch: {sys.implementation.name} {sys.version_info[:3]}")
    machine = normalize_machine(platform.machine())
    expected_machine = normalize_machine(ROWS[row]["arch"])
    if machine != expected_machine or struct.calcsize("P") != 8:
        fail(f"runtime architecture mismatch: {machine}")
    libc_probe = ""
    if row.startswith("musllinux"):
        libc_name, libc_version = platform.libc_ver()
        loaders = list(Path("/lib").glob("ld-musl-*.so.1"))
        if libc_name.lower() != "musl" and not loaders:
            fail(f"musl runtime not detected: {(libc_name, libc_version)}")
        libc_name = "musl"
        if loaders:
            probe = subprocess.run([str(loaders[0]), "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
            libc_probe = probe.stdout.strip()
            if not libc_probe:
                fail("musl loader did not report its version")
    elif row.startswith("linux"):
        libc_name, libc_version = platform.libc_ver()
        if libc_name.lower() != "glibc":
            fail(f"glibc runtime not detected: {(libc_name, libc_version)}")
    elif row.startswith("macos"):
        if sys.platform != "darwin":
            fail(f"macOS wheel is running on {sys.platform}")
        libc_name, libc_version = "darwin", platform.mac_ver()[0]
    else:
        if sys.platform != "win32":
            fail(f"Windows wheel is running on {sys.platform}")
        libc_name, libc_version = "windows", platform.version()

    import formualizer as fz
    import formualizer.formualizer_py as native

    package_path = Path(fz.__file__).resolve()
    native_path = Path(native.__file__).resolve()
    prefix = Path(sys.prefix).resolve()
    paths = sysconfig.get_paths()
    site_roots = {Path(paths[name]).resolve() for name in ("purelib", "platlib")}
    forbidden = [Path(value).resolve() for value in args.forbid]
    require_installed_path(package_path, site_roots, forbidden, "wrapper import")
    require_installed_path(native_path, site_roots, forbidden, "native import")
    if sha256_file(native_path) != audit["native_sha256"] or sha256_file(package_path) != audit["wrapper_sha256"]:
        fail("installed module bytes do not match wheel members")
    if importlib.metadata.version("formualizer") != "0.9.0":
        fail("installed distribution version mismatch")
    dist = importlib.metadata.distribution("formualizer")
    direct_url = dist.locate_file("formualizer-0.9.0.dist-info/direct_url.json")
    if Path(direct_url).exists():
        data = json.loads(Path(direct_url).read_text(encoding="utf-8"))
        if data.get("dir_info", {}).get("editable"):
            fail("editable install detected")
    for site in site_roots:
        for pth in site.glob("*.pth"):
            text = pth.read_text(encoding="utf-8", errors="replace")
            if "formualizer" in text.lower() or any(str(root) in text for root in forbidden):
                fail(f"project-injecting .pth file: {pth}")
        if list(site.glob("*.egg-link")):
            fail("egg-link detected")
    installed_license_hashes: dict[str, str] = {}
    for license_name, expected_hash in (("LICENSE-MIT", MIT_SHA256), ("LICENSE-APACHE", APACHE_SHA256)):
        matches = [Path(dist.locate_file(item)) for item in (dist.files or []) if Path(str(item)).name == license_name]
        if len(matches) != 1 or sha256_file(matches[0]) != expected_hash:
            fail(f"installed {license_name} is absent, duplicated, or noncanonical")
        installed_license_hashes[license_name] = expected_hash

    assertions: list[str] = []
    ast = fz.parse("=SUM(A1:A2)")
    if not ast.to_formula().startswith("=") or not ast.to_dict() or not ast.pretty():
        fail("AST conversion smoke failed")
    parser = fz.Parser()
    if "SUM" not in parser.parse_tokens(fz.tokenize("=SUM(A1:A2)")).to_formula():
        fail("token parser smoke failed")
    assertions.append("parse-and-convert")
    accepted = [f"={'(' * 64}1{')' * 64}", f"={'SUM(' * 64}1{')' * 64}", f"={'IF(A1>0,' * 64}1{',0)' * 64}"]
    hostile = [f"={'(' * 5000}1{')' * 5000}", f"={'-' * 5000}1", f"={'SUM(' * 5000}1{')' * 5000}", f"={'1+(' * 5000}1{')' * 5000}", f"={'IF(A1>0,' * 5000}1{',0)' * 5000}", f"={'{' * 5000}1{'}' * 5000}", f"={'1^' * 5000}1"]
    for formula in accepted:
        fz.parse(formula)
    for formula in hostile:
        for call in (lambda f=formula: fz.parse(f), lambda f=formula: parser.parse_string(f), lambda f=formula: parser.parse_tokens(fz.tokenize(f))):
            try:
                call()
            except fz.ParserError as exc:
                if "Formula nesting too deep (max 72)" not in str(exc):
                    fail("wrong parser depth error")
            else:
                fail("hostile parser input was accepted")
    if parser.parse_string("=A1+1").to_formula().replace(" ", "") != "=A1+1":
        fail("parser did not recover after depth rejection")
    assertions.append("bounded-parser-depth")

    wb = fz.Workbook()
    wb.add_sheet("Sheet1")
    wb.set_value("Sheet1", 1, 1, 20)
    wb.set_value("Sheet1", 2, 1, 22)
    wb.set_formula("Sheet1", 1, 2, "=SUM(A1:A2)")
    if wb.evaluate_cell("Sheet1", 1, 2) != 42:
        fail("workbook evaluation failed")
    wb.set_value("Sheet1", 2, 1, 23)
    if wb.evaluate_cell("Sheet1", 1, 2) != 43:
        fail("workbook recalculation failed")
    wb.register_function("py_add", lambda a, b: a + b, min_args=2, max_args=2)
    wb.set_formula("Sheet1", 1, 3, "=PY_ADD(20,22)")
    if wb.evaluate_cell("Sheet1", 1, 3) != 42:
        fail("Python UDF failed")
    assertions.append("evaluate-recalculate-udf")

    wb.set_value("Sheet1", 2, 1, 22)
    wb.set_formula("Sheet1", 1, 2, "=SUM(A1:A2)")
    wb.evaluate_all()
    precedents = wb.precedents("Sheet1!B1").precedents
    ranges = [item.reference for item in precedents if item.reference.kind is fz.ReferenceKind.Range]
    if len(ranges) != 1 or (ranges[0].declared, ranges[0].resolved, ranges[0].cell_count) != ("Sheet1!A1:A2", "Sheet1!A1:A2", 2):
        fail("inspection precedent range mismatch")
    page = wb.range_page("Sheet1!A1:B2", limit=3)
    if [item.address for item in page.items] != ["Sheet1!A1", "Sheet1!B1", "Sheet1!A2"] or page.next_offset != 3:
        fail("inspection pagination mismatch")
    trace = wb.trace(["Sheet1!B1"], max_depth=2, max_nodes=20)
    if "Sheet1!A1" not in trace.nodes or not trace.links:
        fail("inspection trace mismatch")
    wb.set_value("Sheet1", 3, 1, 1)
    try:
        wb.range_page("Sheet1!A1:B2", expected_stamp=page.stamp)
    except fz.InspectionRevisionMismatchError:
        pass
    else:
        fail("stale inspection stamp was accepted")
    assertions.append("inspection-pagination-trace-stamp")

    payload = wb.to_xlsx_bytes()
    if len(payload) <= 100:
        fail("XLSX export was unexpectedly small")
    for backend in ("calamine", "umya"):
        reopened = fz.Workbook.from_bytes(payload, backend=backend)
        if reopened.evaluate_cell("Sheet1", 1, 2) != 42:
            fail(f"XLSX {backend} roundtrip failed")
    assertions.append("xlsx-calamine-umya")
    required_exports = {"ASTNode", "Workbook", "Parser", "parse", "tokenize"}
    if not required_exports <= set(native.__all__) or any(getattr(fz, name) is not getattr(native, name) for name in required_exports):
        fail("public/native reexports mismatch")
    cfg = fz.EvaluationConfig()
    if cfg.enable_parallel is not True:
        fail("native host parallel default is not enabled")
    assertions.append("native-exports-host-default")

    faulthandler.cancel_dump_traceback_later()
    result = {
        "kind": "smoke", "status": "pass", "phase": args.phase,
        "consumer_row": args.consumer_row, "build_row": row, "candidate_sha": CANDIDATE_SHA,
        "python": platform.python_version(), "implementation": sys.implementation.name,
        "machine": machine, "pointer_width": 64, "os_family": sys.platform,
        "libc": [libc_name, libc_version], "libc_probe": libc_probe,
        "executable": sys.executable, "prefix": str(prefix), "base_prefix": sys.base_prefix,
        "site_packages": sorted(str(path) for path in site_roots),
        "package_path": str(package_path), "package_sha256": sha256_file(package_path),
        "native_path": str(native_path),
        "wheel_sha256": audit["wheel_sha256"], "native_sha256": audit["native_sha256"],
        "installed_license_hashes": installed_license_hashes, "assertions": assertions,
        "xlsx_bytes": len(payload),
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def junit_counts(path: Path) -> dict[str, int]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    counts = {key: sum(int(suite.attrib.get(key, "0")) for suite in suites) for key in ("tests", "failures", "errors", "skipped")}
    if counts["tests"] <= 0 or any(counts[key] for key in ("failures", "errors", "skipped")):
        fail(f"pytest inventory is incomplete or unsuccessful: {counts}")
    counts["testcases"] = sum(1 for _ in root.iter("testcase"))
    if counts["testcases"] != counts["tests"]:
        fail(f"JUnit suite/testcase inventory mismatch: {counts}")
    counts["passed"] = counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"]
    counts["xfailed"] = 0
    return counts


def command_consume_full(args: argparse.Namespace) -> None:
    candidate = Path(args.candidate).resolve()
    verify_candidate(candidate)
    output = Path(args.output).resolve()
    evidence = output.parent
    evidence.mkdir(parents=True, exist_ok=True)
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    staging = work / "stage"
    helper, config = stage_tests(candidate, staging)
    wheelhouse = Path(args.wheelhouse).resolve()
    audit = audit_wheel(wheelhouse, args.row, candidate)
    wheel = one_wheel(wheelhouse, args.row)
    venv = work / "venv"
    if venv.exists():
        shutil.rmtree(venv)
    env = isolated_env()
    run([sys.executable, "-I", "-m", "venv", str(venv)], timeout=180, env=env)
    python = venv_python(venv)
    run([str(python), "-I", "-m", "pip", "--isolated", "install", "--no-index", "--no-deps", "--only-binary=:all:", str(wheel)], timeout=180, env=env)
    run([str(python), "-I", "-m", "pip", "--isolated", "install", "--only-binary=:all:", "pytest==9.0.3", "pytest-cov==6.1.1", "pytest-timeout==2.4.0", "openpyxl==3.1.5", "packaging==25.0"], timeout=600, env=env)
    smoke_common = [
        str(python), "-I", "-B", str(helper), "installed-smoke",
        "--wheelhouse", str(wheelhouse), "--licenses", str(staging),
        "--row", args.row, "--consumer-row", args.consumer_row,
        "--python-version", args.python_version,
        "--forbid", str(candidate), "--forbid", str(Path(args.driver).resolve()),
        "--forbid", str(staging),
    ]
    pre_smoke = evidence / f"smoke-pre-{args.consumer_row}.json"
    pre_log = evidence / f"smoke-pre-{args.consumer_row}.log"
    code, timed_out = run_logged(
        smoke_common + ["--phase", "pre-suite", "--output", str(pre_smoke)],
        pre_log, cwd=staging, timeout=180, env=env,
    )
    if timed_out or code != 0 or not pre_smoke.is_file():
        fail("pre-suite installed smoke failed; diagnostics were preserved")

    junit = evidence / f"pytest-{args.consumer_row}.xml"
    pytest_log = evidence / f"pytest-{args.consumer_row}.log"
    pytest_argv = [
        str(python), "-I", "-B", "-m", "pytest", "-p", "pytest_timeout",
        "--import-mode=importlib", "-c", str(config), str(staging / "tests"),
        "-o", "addopts=", "--strict-markers", "--strict-config",
        "--junitxml", str(junit),
    ]
    code, timed_out = run_logged(pytest_argv, pytest_log, cwd=staging, timeout=1200, env=env)
    if timed_out or code != 0 or not junit.is_file():
        fail("pytest failed or timed out; stdout/JUnit/smoke diagnostics were preserved")
    counts = junit_counts(junit)
    pytest_text = pytest_log.read_text(encoding="utf-8")
    collected_match = re.search(r"collected (\d+) items", pytest_text)
    if collected_match is None:
        fail("pytest output does not contain the collected test inventory")
    collected = int(collected_match.group(1))
    deselected_match = re.search(r"(\d+) deselected", pytest_text)
    deselected = int(deselected_match.group(1)) if deselected_match else 0
    if deselected != 0 or collected != counts["tests"]:
        fail(f"pytest collection/JUnit mismatch: collected={collected}, deselected={deselected}, junit={counts}")

    post_smoke = evidence / f"smoke-post-{args.consumer_row}.json"
    post_log = evidence / f"smoke-post-{args.consumer_row}.log"
    code, timed_out = run_logged(
        smoke_common + ["--phase", "post-suite", "--output", str(post_smoke)],
        post_log, cwd=staging, timeout=180, env=env,
    )
    if timed_out or code != 0 or not post_smoke.is_file():
        fail("post-suite installed-byte audit/smoke failed; diagnostics were preserved")
    pre = json.loads(pre_smoke.read_text(encoding="utf-8"))
    post = json.loads(post_smoke.read_text(encoding="utf-8"))
    if pre != {**post, "phase": "pre-suite"}:
        fail("pre/post installed smoke identity changed across the suite")
    freeze = run([str(python), "-I", "-m", "pip", "--isolated", "freeze", "--all"], env=env).stdout.splitlines()
    run([str(python), "-I", "-m", "pip", "--isolated", "check"], env=env)
    provisioning = Path(args.provisioning)
    if not provisioning.is_file() or provisioning.stat().st_size == 0:
        fail("Python provisioning evidence is absent")
    report = {
        "kind": "consumer", "level": "full-suite", "status": "pass",
        "consumer_row": args.consumer_row, "build_row": args.row,
        "candidate_sha": CANDIDATE_SHA,
        "workflow_sha": require_sha(args.workflow_sha, "workflow_sha"),
        "run_id": args.run_id, "run_attempt": args.run_attempt,
        "wheel_sha256": audit["wheel_sha256"],
        "smoke_pre_sha256": sha256_file(pre_smoke),
        "smoke_post_sha256": sha256_file(post_smoke),
        "smoke_pre_log_sha256": sha256_file(pre_log),
        "smoke_post_log_sha256": sha256_file(post_log),
        "pytest_counts": counts, "collected": collected, "deselected": deselected,
        "pytest_output_sha256": sha256_file(pytest_log),
        "pytest_junit_sha256": sha256_file(junit),
        "provisioning_filename": provisioning.name,
        "provisioning_sha256": sha256_file(provisioning),
        "installed_packages": sorted(freeze),
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command_wrap_musl(args: argparse.Namespace) -> None:
    smoke_path = Path(args.smoke_report)
    smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
    expected_digest = MUSL_DIGESTS[args.row]
    if smoke.get("status") != "pass" or smoke.get("consumer_row") != args.consumer_row or smoke.get("phase") != "musl":
        fail("musl smoke report is missing or mismatched")
    if args.container_digest != expected_digest or not args.container_image.endswith("@" + expected_digest):
        fail("musl container digest is not the pinned row digest")
    container_evidence = Path(args.container_evidence)
    if not container_evidence.is_file() or expected_digest not in container_evidence.read_text(encoding="utf-8"):
        fail("musl container evidence is absent or does not bind the digest")
    report = {
        "kind": "consumer", "level": "bounded-musl-smoke", "status": "pass",
        "consumer_row": args.consumer_row, "build_row": args.row,
        "candidate_sha": CANDIDATE_SHA, "workflow_sha": require_sha(args.workflow_sha, "workflow_sha"),
        "run_id": args.run_id, "run_attempt": args.run_attempt,
        "wheel_sha256": smoke["wheel_sha256"], "container_image": args.container_image,
        "container_digest": args.container_digest,
        "container_evidence_sha256": sha256_file(container_evidence),
        "smoke_sha256": sha256_file(smoke_path),
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command_consume_musl(args: argparse.Namespace) -> None:
    wheelhouse = Path(args.wheelhouse).resolve()
    licenses = Path(args.licenses).resolve()
    audit_wheel(wheelhouse, args.row, licenses)
    wheel = one_wheel(wheelhouse, args.row)
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    venv = work / "venv"
    if venv.exists():
        shutil.rmtree(venv)
    env = isolated_env()
    run([sys.executable, "-I", "-m", "venv", str(venv)], timeout=180, env=env)
    python = venv_python(venv)
    run([str(python), "-I", "-m", "pip", "--isolated", "install", "--no-index", "--no-deps", "--only-binary=:all:", str(wheel)], timeout=180, env=env)
    run([str(python), "-I", "-B", str(Path(__file__).resolve()), "installed-smoke", "--wheelhouse", str(wheelhouse), "--licenses", str(licenses), "--row", args.row, "--consumer-row", args.consumer_row, "--python-version", args.python_version, "--phase", "musl", "--output", args.output, "--forbid", str(Path(__file__).resolve().parent), "--forbid", str(licenses)], cwd=work, timeout=180, env=env)


def command_finalize_build(args: argparse.Namespace) -> None:
    path = Path(args.report)
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("kind") != "build" or report.get("status") != "pass":
        fail("only a passing build report can be finalized")
    if not args.artifact_id.isdigit() or DIGEST_RE.fullmatch(args.artifact_digest.removeprefix("sha256:")) is None:
        fail("invalid upload-artifact output syntax")
    evidence_paths = {
        "compiler": Path(args.compiler), "native_inspection": Path(args.native_inspection),
        "builder": Path(args.builder),
    }
    for label, evidence_path in evidence_paths.items():
        if not evidence_path.is_file() or evidence_path.stat().st_size == 0:
            fail(f"required {label} evidence is absent or empty")
    compiler = json.loads(evidence_paths["compiler"].read_text(encoding="utf-8"))
    if compiler.get("kind") != "compiler" or compiler.get("status") != "pass" or compiler.get("build_row") != report.get("build_row") or compiler.get("target") != report.get("resolved_target"):
        fail("structured compiler proof does not match the build report")
    native_text = evidence_paths["native_inspection"].read_text(encoding="utf-8", errors="strict")
    expected_native = {"ELF": ("ELF", "Dynamic section"), "Mach-O": ("Architectures", "compatibility version"), "PE": ("Format:", "Import")}[ROWS[report["build_row"]]["binary"]]
    if not any(marker in native_text for marker in expected_native):
        fail("native inspection evidence does not identify the expected binary family")
    report["upload_output_artifact_id"] = args.artifact_id
    report["upload_output_artifact_digest"] = args.artifact_digest
    report["upload_identity_scope"] = "syntax-captured action outputs; wheel continuity is independently SHA-256 checked after same-run exact-name download"
    for label, evidence_path in evidence_paths.items():
        report[f"{label}_filename"] = evidence_path.name
        report[f"{label}_sha256"] = sha256_file(evidence_path)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def evidence_file(root: Path, name: str) -> Path:
    matches = list(root.rglob(name))
    if len(matches) != 1 or not matches[0].is_file() or matches[0].stat().st_size == 0:
        fail(f"required evidence file inventory mismatch: {name}: {matches}")
    return matches[0]


def read_json_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"corrupt JSON evidence {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON evidence is not an object: {path}")
    return value


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value.removeprefix("sha256:")) is None:
        fail(f"missing or malformed SHA-256: {label}")
    return value


def require_recorded_installed_path(value: Any, roots: Any, row: str, label: str) -> None:
    if not isinstance(value, str) or not isinstance(roots, list) or not roots or not all(isinstance(root, str) for root in roots):
        fail(f"{label} recorded path inventory is malformed")
    path_class = PureWindowsPath if ROWS[row]["family"] == "win" else PurePosixPath
    child = path_class(value)
    parsed_roots = [path_class(root) for root in roots]
    if str(child) != value or any(str(parsed) != original for parsed, original in zip(parsed_roots, roots)):
        fail(f"{label} producer paths are not canonical")
    if not child.is_absolute() or any(part == ".." for part in child.parts):
        fail(f"{label} is not an absolute normalized producer path")
    if path_class is PureWindowsPath and (not child.drive or any(not root.drive for root in parsed_roots)):
        fail(f"{label} lacks an absolute Windows drive")
    if any(not root.is_absolute() or any(part == ".." for part in root.parts) for root in parsed_roots):
        fail(f"{label} site-packages root is malformed")
    for root in parsed_roots:
        try:
            child.relative_to(root)
            return
        except ValueError:
            continue
    fail(f"{label} does not resolve inside the producer's site-packages")


def validate_smoke(smoke: dict[str, Any], *, key: str, row: str, phase: str,
                   wheel_sha256: str, native_sha256: str, package_sha256: str) -> None:
    expected_python = key.rsplit("py", 1)[1]
    required = {
        "kind": "smoke", "status": "pass", "phase": phase,
        "consumer_row": key, "build_row": row, "candidate_sha": CANDIDATE_SHA,
        "implementation": "cpython", "pointer_width": 64,
        "wheel_sha256": wheel_sha256, "native_sha256": native_sha256,
        "package_sha256": package_sha256,
    }
    if any(smoke.get(name) != value for name, value in required.items()):
        fail(f"smoke identity mismatch: {key}/{phase}")
    if not str(smoke.get("python", "")).startswith(expected_python + "."):
        fail(f"smoke Python mismatch: {key}")
    if normalize_machine(str(smoke.get("machine", ""))) != normalize_machine(ROWS[row]["arch"]):
        fail(f"smoke architecture mismatch: {key}")
    libc = smoke.get("libc")
    if not isinstance(libc, list) or len(libc) != 2 or libc[0].lower() != ROWS[row]["libc"]:
        fail(f"smoke libc/OS family mismatch: {key}: {libc}")
    if row.startswith("musllinux") and not smoke.get("libc_probe"):
        fail(f"musl loader evidence missing: {key}")
    if set(smoke.get("assertions", [])) != SMOKE_ASSERTIONS:
        fail(f"smoke assertion inventory mismatch: {key}")
    if smoke.get("installed_license_hashes") != {"LICENSE-MIT": MIT_SHA256, "LICENSE-APACHE": APACHE_SHA256}:
        fail(f"installed licenses mismatch: {key}")
    for name in ("wheel_sha256", "native_sha256", "package_sha256"):
        require_digest(smoke.get(name), f"{key}.{name}")
    site_roots = smoke.get("site_packages", [])
    require_recorded_installed_path(smoke.get("package_path"), site_roots, row, "recorded wrapper")
    require_recorded_installed_path(smoke.get("native_path"), site_roots, row, "recorded native module")


def command_aggregate(args: argparse.Namespace) -> None:
    root = Path(args.evidence).resolve()
    workflow_sha = require_sha(args.workflow_sha, "workflow_sha")
    run_id = args.run_id
    run_attempt = args.run_attempt
    if not run_id.isdigit() or not run_attempt.isdigit():
        fail("expected run ID/attempt are not numeric")
    try:
        needs = json.loads(args.needs_results)
    except json.JSONDecodeError as exc:
        fail(f"needs results are not JSON: {exc}")
    expected_needs = {"preflight", "build-linux", "build-host", "consume-full", "consume-musl"}
    if not isinstance(needs, dict) or set(needs) != expected_needs or any(value != "success" for value in needs.values()):
        fail(f"required job result is not success: {needs}")
    for path in root.rglob("*.json"):
        read_json_file(path)

    builds: dict[str, dict[str, Any]] = {}
    upload_ids: set[str] = set()
    for row in ROWS:
        report_path = evidence_file(root, f"build-{row}.json")
        item = read_json_file(report_path)
        builds[row] = item
        required_build = {
            "kind": "build", "status": "pass", "build_row": row,
            "candidate_sha": CANDIDATE_SHA, "candidate_tree": CANDIDATE_TREE,
            "workflow_sha": workflow_sha, "run_id": run_id, "run_attempt": run_attempt,
            "release_recipe_hash": RELEASE_SHA256, "cargo_lock_hash": LOCK_SHA256,
            "action_commit": "e83996d129638aa358a18fbd1dfb82f0b0fb5d3b",
            "resolved_target": ROWS[row]["target"],
        }
        if any(item.get(key) != value for key, value in required_build.items()):
            fail(f"invalid build provenance report: {row}")
        wheel_hash = require_digest(item.get("wheel_sha256"), f"{row}.wheel_sha256")
        require_digest(item.get("native_sha256"), f"{row}.native_sha256")
        require_digest(item.get("wrapper_sha256"), f"{row}.wrapper_sha256")
        artifact_id = str(item.get("upload_output_artifact_id", ""))
        require_digest(item.get("upload_output_artifact_digest"), f"{row}.upload output digest")
        if not artifact_id.isdigit() or artifact_id in upload_ids:
            fail(f"missing/duplicate upload-artifact output ID: {row}")
        upload_ids.add(artifact_id)
        if not str(item.get("upload_identity_scope", "")).startswith("syntax-captured action outputs"):
            fail(f"artifact identity scope is overstated or missing: {row}")
        expected_names = {
            "compiler": f"compiler-{row}.json",
            "native_inspection": f"native-inspection-{row}.txt",
            "builder": f"builder-{row}.txt",
        }
        for label in ("compiler", "native_inspection", "builder"):
            if item.get(f"{label}_filename") != expected_names[label]:
                fail(f"{label} evidence identity mismatch: {row}")
            evidence_path = evidence_file(root, expected_names[label])
            if sha256_file(evidence_path) != item.get(f"{label}_sha256"):
                fail(f"{label} evidence digest mismatch: {row}")
        native_text = evidence_file(root, f"native-inspection-{row}.txt").read_text(encoding="utf-8")
        native_markers = {"ELF": "ELF", "Mach-O": "compatibility version", "PE": "Format:"}
        if native_markers[ROWS[row]["binary"]] not in native_text:
            fail(f"native inspection family mismatch: {row}")
        builder_text = evidence_file(root, f"builder-{row}.txt").read_text(encoding="utf-8")
        if row in BUILD_IMAGES:
            if f"selected_build_image={BUILD_IMAGES[row]}" not in builder_text or "repo_digests=" not in builder_text or re.search(r"sha256:[0-9a-f]{64}", builder_text) is None:
                fail(f"Linux builder image/digest evidence mismatch: {row}")
        elif "runner_image_os=" not in builder_text or "runner_image_version=" not in builder_text:
            fail(f"host builder image evidence mismatch: {row}")
        compiler = read_json_file(evidence_file(root, f"compiler-{row}.json"))
        rustc = str(compiler.get("rustc_vv", compiler.get("rustc_version", "")))
        if compiler.get("kind") != "compiler" or compiler.get("status") != "pass" or compiler.get("build_row") != row or compiler.get("target") != ROWS[row]["target"] or (compiler.get("runner_os"), compiler.get("runner_arch")) != BUILD_RUNNERS[row] or "rustc 1.93.0 (254b59607 2026-01-19)" not in rustc or compiler.get("maturin_version") != "maturin 1.11.5":
            fail(f"compiler evidence schema mismatch: {row}")
        for name in ("runner_image_os", "runner_image_version", "rustc_path", "linker", "linker_source", "c_compiler_path", "build_python"):
            if not compiler.get(name):
                fail(f"compiler evidence lacks {name}: {row}")
        if f"runner_image_os={compiler['runner_image_os']}" not in builder_text or f"runner_image_version={compiler['runner_image_version']}" not in builder_text:
            fail(f"runner image facts do not reconcile: {row}")
        if not isinstance(compiler.get("effective_flags"), dict) or not isinstance(compiler.get("cargo_configs"), list):
            fail(f"compiler flags/config evidence malformed: {row}")
        if compiler["effective_flags"].get("CARGO_BUILD_TARGET", "") not in ("", ROWS[row]["target"]):
            fail(f"compiler evidence has a mismatched CARGO_BUILD_TARGET: {row}")
        for config in compiler["cargo_configs"]:
            if not isinstance(config, dict) or not config.get("path") or DIGEST_RE.fullmatch(str(config.get("sha256", ""))) is None or not isinstance(config.get("reviewed_cross_settings"), str):
                fail(f"Cargo config evidence malformed: {row}")
            settings_text = config["reviewed_cross_settings"]
            if row not in BUILD_IMAGES:
                try:
                    settings = json.loads(settings_text)
                except json.JSONDecodeError:
                    fail(f"host Cargo config summary is malformed: {row}")
                identities: set[tuple[str, str]] = set()
                if not isinstance(settings, list):
                    fail(f"host Cargo config summary is not a list: {row}")
                for setting in settings:
                    if not isinstance(setting, dict) or set(setting) != {"target", "key", "value"} or re.fullmatch(r"[a-z0-9][a-z0-9_-]*", str(setting["target"])) is None or setting["key"] not in {"linker", "runner", "rustflags"} or not isinstance(setting["value"], str):
                        fail(f"host Cargo config setting is outside the narrow grammar: {row}")
                    identity = (setting["target"], setting["key"])
                    if identity in identities:
                        fail(f"host Cargo config setting is duplicated: {row}")
                    identities.add(identity)
            elif re.search(r"(?i)rustc(?:-wrapper|-workspace-wrapper)?=", settings_text):
                fail(f"Cargo config compiler override recorded: {row}")
        link_args = compiler.get("link_args_probe")
        if not isinstance(link_args, dict) or link_args.get("returncode") != 0 or not str(link_args.get("output", "")).strip() or Path(str(compiler["linker"])).name.lower() not in str(link_args["output"]).lower():
            fail(f"rustc link-args probe is missing or contradictory: {row}")
        if row in BUILD_IMAGES:
            raw = evidence_file(root, f"compiler-{row}.raw")
            raw_text = raw.read_text(encoding="utf-8")
            raw_values, raw_configs, raw_blocks = parse_linux_compiler_raw(raw_text, row)
            if sha256_file(raw) != compiler.get("raw_sha256"):
                fail(f"raw in-container compiler proof digest mismatch: {row}")
            reconciled = {
                "rustc_path": raw_values["rustc_path"], "target_libdir": raw_values["target_libdir"],
                "linker": raw_values["linker"], "linker_path": raw_values["linker_path"],
                "linker_source": raw_values["linker_source"], "c_compiler_path": raw_values["c_compiler_path"],
                "rustc_vv": raw_blocks["rustc_vv"], "cargo_configs": raw_configs,
            }
            if any(compiler.get(name) != value for name, value in reconciled.items()):
                fail(f"normalized/raw compiler proof mismatch: {row}")
        else:
            probe_family = "msvc" if row == "windows-x64" else "apple"
            for probe_name in ("c_compiler_probe", "linker_probe"):
                probe = compiler.get(probe_name)
                if not isinstance(probe, dict):
                    fail(f"host compiler/linker probe missing: {row}/{probe_name}")
                expected_family = "msvc-cl" if probe_family == "msvc" and probe_name == "c_compiler_probe" else "msvc-link" if probe_family == "msvc" else "apple-clang"
                require_recognized_tool_probe(probe, expected_family, f"{row}/{probe_name}")
        if wheel_hash != item["wheel_sha256"]:
            fail(f"wheel hash normalization failure: {row}")

    full_rows = ("linux-x86_64", "linux-aarch64", "windows-x64", "macos-x86_64", "macos-aarch64")
    consumer_keys = [f"{row}-py{version}" for row in full_rows for version in ("3.10", "3.13")]
    consumer_keys += [f"{row}-py{version}" for row in MUSL_DIGESTS for version in ("3.10", "3.13")]
    for key in consumer_keys:
        row = key.rsplit("-py", 1)[0]
        item = read_json_file(evidence_file(root, f"consumer-{key}.json"))
        level = "bounded-musl-smoke" if row in MUSL_DIGESTS else "full-suite"
        required_consumer = {
            "kind": "consumer", "status": "pass", "level": level,
            "consumer_row": key, "build_row": row, "candidate_sha": CANDIDATE_SHA,
            "workflow_sha": workflow_sha, "run_id": run_id, "run_attempt": run_attempt,
            "wheel_sha256": builds[row]["wheel_sha256"],
        }
        if any(item.get(name) != value for name, value in required_consumer.items()):
            fail(f"consumer provenance mismatch: {key}")
        if level == "full-suite":
            junit = evidence_file(root, f"pytest-{key}.xml")
            pytest_log = evidence_file(root, f"pytest-{key}.log")
            pre_path = evidence_file(root, f"smoke-pre-{key}.json")
            post_path = evidence_file(root, f"smoke-post-{key}.json")
            expected_provisioning = f"python-provisioning-{key}.txt"
            if item.get("provisioning_filename") != expected_provisioning:
                fail(f"Python provisioning evidence identity mismatch: {key}")
            provisioning = evidence_file(root, expected_provisioning)
            provisioning_text = provisioning.read_text(encoding="utf-8")
            expected_python = key.rsplit("py", 1)[1]
            if expected_python not in provisioning_text:
                fail(f"Python provisioning version evidence mismatch: {key}")
            if key == "macos-aarch64-py3.10" and ("uv 0.12.10" not in provisioning_text or "c2ddcefee6ae51286001dc22320434676adcc89362330823b409eac51a101a4b" not in provisioning_text):
                fail("pinned uv/Python download provenance is missing")
            pre_log = evidence_file(root, f"smoke-pre-{key}.log")
            post_log = evidence_file(root, f"smoke-post-{key}.log")
            if sha256_file(junit) != item.get("pytest_junit_sha256") or sha256_file(pytest_log) != item.get("pytest_output_sha256") or sha256_file(pre_path) != item.get("smoke_pre_sha256") or sha256_file(post_path) != item.get("smoke_post_sha256") or sha256_file(pre_log) != item.get("smoke_pre_log_sha256") or sha256_file(post_log) != item.get("smoke_post_log_sha256") or sha256_file(provisioning) != item.get("provisioning_sha256"):
                fail(f"full consumer evidence digest mismatch: {key}")
            counts = junit_counts(junit)
            if counts != item.get("pytest_counts") or item.get("collected") != counts["tests"] or item.get("deselected") != 0:
                fail(f"JUnit/collection reconciliation mismatch: {key}")
            validate_smoke(read_json_file(pre_path), key=key, row=row, phase="pre-suite", wheel_sha256=item["wheel_sha256"], native_sha256=builds[row]["native_sha256"], package_sha256=builds[row]["wrapper_sha256"])
            validate_smoke(read_json_file(post_path), key=key, row=row, phase="post-suite", wheel_sha256=item["wheel_sha256"], native_sha256=builds[row]["native_sha256"], package_sha256=builds[row]["wrapper_sha256"])
        else:
            smoke_path = evidence_file(root, f"smoke-{key}.json")
            container_path = evidence_file(root, f"container-{key}.txt")
            if sha256_file(smoke_path) != item.get("smoke_sha256") or sha256_file(container_path) != item.get("container_evidence_sha256"):
                fail(f"musl consumer evidence digest mismatch: {key}")
            if item.get("container_digest") != MUSL_DIGESTS[row] or not str(item.get("container_image", "")).endswith("@" + MUSL_DIGESTS[row]):
                fail(f"musl digest mismatch: {key}")
            validate_smoke(read_json_file(smoke_path), key=key, row=row, phase="musl", wheel_sha256=item["wheel_sha256"], native_sha256=builds[row]["native_sha256"], package_sha256=builds[row]["wrapper_sha256"])

    expected_files: set[str] = set()
    for row in ROWS:
        expected_files.update({f"build-{row}.json", f"compiler-{row}.json", f"builder-{row}.txt", f"native-inspection-{row}.txt"})
        if row in BUILD_IMAGES:
            expected_files.add(f"compiler-{row}.raw")
    for key in consumer_keys:
        if key.startswith("musllinux-"):
            expected_files.update({f"consumer-{key}.json", f"smoke-{key}.json", f"container-{key}.txt"})
        else:
            expected_files.update({
                f"consumer-{key}.json", f"smoke-pre-{key}.json", f"smoke-pre-{key}.log",
                f"smoke-post-{key}.json", f"smoke-post-{key}.log",
                f"pytest-{key}.xml", f"pytest-{key}.log", f"python-provisioning-{key}.txt",
            })
    actual_files = [path.name for path in root.rglob("*") if path.is_file()]
    if len(actual_files) != len(set(actual_files)) or set(actual_files) != expected_files:
        fail(f"complete evidence file inventory mismatch: {sorted(actual_files)}")

    result = {
        "status": "pass", "candidate_sha": CANDIDATE_SHA,
        "workflow_sha": workflow_sha, "run_id": run_id, "run_attempt": run_attempt,
        "required_job_results": needs, "build_rows": sorted(builds),
        "full_suite_rows": sorted(key for key in consumer_keys if not key.startswith("musllinux-")),
        "bounded_musl_rows": sorted(key for key in consumer_keys if key.startswith("musllinux-")),
        "artifact_identity_scope": "upload action outputs syntax-captured only; same-run exact-name download plus audited wheel SHA-256 continuity is enforced",
    }
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subs = root.add_subparsers(dest="command", required=True)
    pre = subs.add_parser("preflight")
    for name in ("candidate-sha", "workflow-sha", "expected-workflow-sha", "event-name", "ref", "repository", "workflow-ref", "driver", "candidate"):
        pre.add_argument("--" + name, required=True)
    pre.set_defaults(func=command_preflight)
    verify = subs.add_parser("verify-source")
    verify.add_argument("--candidate", required=True)
    verify.set_defaults(func=command_verify_source)
    verify_driver = subs.add_parser("verify-driver")
    verify_driver.add_argument("--driver", required=True)
    verify_driver.add_argument("--workflow-sha", required=True)
    verify_driver.set_defaults(func=command_verify_driver)
    compiler = subs.add_parser("compiler-proof")
    for name in ("candidate", "row", "target", "runner-os", "runner-arch", "runner-image-os", "runner-image-version", "output"):
        compiler.add_argument("--" + name, required=True)
    compiler.set_defaults(func=command_compiler_proof)
    linux_compiler = subs.add_parser("linux-compiler-proof")
    for name in ("candidate", "raw", "row", "runner-os", "runner-arch", "runner-image-os", "runner-image-version", "output"):
        linux_compiler.add_argument("--" + name, required=True)
    linux_compiler.set_defaults(func=command_linux_compiler_proof)
    audit = subs.add_parser("audit-wheel")
    for name in ("wheelhouse", "candidate", "row", "compiler-evidence", "workflow-sha", "action-commit", "runner-image", "runner-arch", "run-id", "run-attempt", "output"):
        audit.add_argument("--" + name, required=True)
    audit.add_argument("--native-output")
    audit.set_defaults(func=command_audit_wheel)
    smoke = subs.add_parser("installed-smoke")
    for name in ("wheelhouse", "licenses", "row", "consumer-row", "python-version", "output"):
        smoke.add_argument("--" + name, required=True)
    smoke.add_argument("--phase", required=True, choices=("pre-suite", "post-suite", "musl"))
    smoke.add_argument("--forbid", action="append", default=[])
    smoke.set_defaults(func=command_installed_smoke)
    consume = subs.add_parser("consume-full")
    for name in ("wheelhouse", "candidate", "driver", "work", "row", "consumer-row", "python-version", "workflow-sha", "run-id", "run-attempt", "provisioning", "output"):
        consume.add_argument("--" + name, required=True)
    consume.set_defaults(func=command_consume_full)
    musl = subs.add_parser("wrap-musl")
    for name in ("smoke-report", "row", "consumer-row", "workflow-sha", "run-id", "run-attempt", "container-image", "container-digest", "container-evidence", "output"):
        musl.add_argument("--" + name, required=True)
    musl.set_defaults(func=command_wrap_musl)
    consume_musl = subs.add_parser("consume-musl")
    for name in ("wheelhouse", "licenses", "work", "row", "consumer-row", "python-version", "output"):
        consume_musl.add_argument("--" + name, required=True)
    consume_musl.set_defaults(func=command_consume_musl)
    finalize = subs.add_parser("finalize-build")
    for name in ("report", "artifact-id", "artifact-digest", "compiler", "native-inspection", "builder"):
        finalize.add_argument("--" + name, required=True)
    finalize.set_defaults(func=command_finalize_build)
    aggregate = subs.add_parser("aggregate")
    aggregate.add_argument("--evidence", required=True)
    aggregate.add_argument("--workflow-sha", required=True)
    aggregate.add_argument("--run-id", required=True)
    aggregate.add_argument("--run-attempt", required=True)
    aggregate.add_argument("--needs-results", required=True)
    aggregate.add_argument("--output", required=True)
    aggregate.set_defaults(func=command_aggregate)
    return root


def main(argv: list[str] | None = None) -> None:
    args = parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
