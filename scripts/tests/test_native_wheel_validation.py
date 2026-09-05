from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/native-wheel-validation.py"
WORKFLOW = ROOT / ".github/workflows/native-release-validation.yml"
LINUX_HOOK = ROOT / "scripts/native-linux-compiler-proof.sh"
SPEC = importlib.util.spec_from_file_location("native_wheel_validation", HELPER)
assert SPEC is not None and SPEC.loader is not None
nv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nv)


def record(entries: dict[str, bytes], corrupt: str | None = None) -> bytes:
    rows: list[list[str]] = []
    for name, data in entries.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if name == corrupt:
            digest = "A" * 43
        rows.append([name, "sha256=" + digest, str(len(data))])
    rows.append(["formualizer-0.9.0.dist-info/RECORD", "", ""])
    out = []
    for row in rows:
        out.append(",".join(row))
    return ("\n".join(out) + "\n").encode()


def raw_compiler_fixture(row: str) -> str:
    values = {
        "format": "native-compiler-proof-v2", "build_row": row,
        "target": nv.ROWS[row]["target"], "config_scan": "pass",
        "cargo_build_target": nv.ROWS[row]["target"] if row.endswith("aarch64") else "",
        "target_rustflags": "", "rustc_version": "rustc 1.93.0 (254b59607 2026-01-19)",
        "rustc_path": "/toolchain/bin/rustc", "target_libdir": f"/toolchain/lib/rustlib/{nv.ROWS[row]['target']}/lib", "linker": "cc",
        "linker_path": "/usr/bin/cc", "linker_source": "fixture", "c_compiler_path": "/usr/bin/cc",
        "maturin_version": "maturin 1.11.5", "build_python_status": "not-selected-by-validator",
        "build_python_executable": "", "build_python_version": "", "cc": "", "cxx": "",
        "cflags": "", "cppflags": "", "cxxflags": "", "ldflags": "", "archflags": "",
        "macosx_deployment_target": "", "sdkroot": "",
    }
    lines = [f"{key}={values[key]}" for key in nv.RAW_SCALARS]
    lines += [
        "rustc_vv_begin", "rustc 1.93.0 (254b59607 2026-01-19)", "release: 1.93.0",
        "cargo 1.93.0 fixture", nv.ROWS[row]["target"], "rustc_vv_end", "link_args_begin", '"cc" fixture link args',
        "link_args_end", "c_compiler_begin", "gcc (GCC) 1.0 fixture", "c_compiler_end",
        "linker_probe_begin", "gcc (GCC) 1.0 fixture", "linker_probe_end",
    ]
    return "\n".join(lines) + "\n"


def elf(machine: int = 62) -> bytes:
    data = bytearray(64)
    data[:4] = b"\x7fELF"
    data[4] = 2
    data[5] = 1
    data[18:20] = machine.to_bytes(2, "little")
    return bytes(data)


def make_wheel(directory: Path, *, platform_tag: str = "manylinux_2_17_x86_64",
               version: str = "0.9.0", abi: str = "abi3", machine: int = 62,
               corrupt_record: str | None = None, corrupt_license: bool = False,
               extra_wheel: bool = False) -> Path:
    name = f"formualizer-{version}-cp310-{abi}-{platform_tag}.whl"
    wheel = directory / name
    dist = "formualizer-0.9.0.dist-info"
    entries = {
        "formualizer/__init__.py": b"from .formualizer_py import *\n",
        "formualizer/__init__.pyi": b"",
        "formualizer/formualizer_py.pyi": b"",
        "formualizer/py.typed": b"",
        "formualizer/formualizer_py.abi3.so": elf(machine),
        f"{dist}/METADATA": (
            "Metadata-Version: 2.4\nName: formualizer\nVersion: 0.9.0\n"
            "Requires-Python: >=3.10\nLicense-Expression: MIT\n"
            "License-File: LICENSE-MIT\nLicense-File: LICENSE-APACHE\n\n"
        ).encode(),
        f"{dist}/WHEEL": f"Wheel-Version: 1.0\nTag: cp310-abi3-{platform_tag}\n\n".encode(),
        f"{dist}/licenses/LICENSE-MIT": (ROOT / "LICENSE-MIT").read_bytes(),
        f"{dist}/licenses/LICENSE-APACHE": (ROOT / "LICENSE-APACHE").read_bytes(),
    }
    if corrupt_license:
        entries[f"{dist}/licenses/LICENSE-MIT"] = b"not the license"
    entries[f"{dist}/RECORD"] = record(entries, corrupt_record)
    with zipfile.ZipFile(wheel, "w", zipfile.ZIP_STORED) as archive:
        for member, data in entries.items():
            archive.writestr(member, data)
    if extra_wheel:
        (directory / "extra.whl").write_bytes(b"x")
    return wheel


def parse_workflow(text: str) -> dict:
    ruby = r'''
require "yaml"
require "json"
convert = nil
convert = lambda do |node|
  case node
  when Psych::Nodes::Mapping
    Hash[node.children.each_slice(2).map { |key, value| [convert.call(key), convert.call(value)] }]
  when Psych::Nodes::Sequence
    node.children.map { |value| convert.call(value) }
  when Psych::Nodes::Scalar
    node.value
  else
    raise "unsupported YAML node #{node.class}"
  end
end
puts JSON.generate(convert.call(YAML.parse(STDIN.read).root))
'''
    result = subprocess.run(["ruby", "-e", ruby], input=text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        raise AssertionError("workflow YAML did not parse: " + result.stderr)
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise AssertionError("workflow YAML root is not a mapping")
    return value


def assert_workflow_contract(text: str) -> None:
    workflow = parse_workflow(text)
    if set(workflow.get("on", {})) != {"workflow_dispatch"}:
        raise AssertionError(f"trigger allowlist mismatch: {workflow.get('on')}")
    if workflow.get("permissions") != {"contents": "read"}:
        raise AssertionError("read-only top-level permissions mismatch")
    jobs = workflow.get("jobs", {})
    expected_jobs = {"preflight", "build-linux", "build-host", "consume-full", "consume-musl", "complete"}
    if set(jobs) != expected_jobs or any("permissions" in job for job in jobs.values()):
        raise AssertionError("job inventory or job-level permissions changed")
    required_pins = {
        "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803",
        "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
        "PyO3/maturin-action@e83996d129638aa358a18fbd1dfb82f0b0fb5d3b",
        "actions/upload-artifact@b7c566a772e6b6bfb58ed0dc250532a479d7789f",
        "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        "astral-sh/setup-uv@37802adc94f370d6bfd71619e3f0bf239e1f3b78",
    }
    for pin in required_pins:
        if pin not in text:
            raise AssertionError(f"missing reviewed action pin: {pin}")
    if "\n  workflow_dispatch:\n" not in text:
        raise AssertionError("manual trigger missing")
    trigger_prefix = text.split("permissions:", 1)[0]
    for trigger in ("push:", "pull_request:", "workflow_call:", "workflow_run:", "repository_dispatch:"):
        if trigger in trigger_prefix:
            raise AssertionError(f"forbidden trigger: {trigger}")
    if "permissions:\n  contents: read" not in text:
        raise AssertionError("read-only top-level permissions missing")
    forbidden = ("id-token: write", "contents: write", "attest-build", "softprops/action-gh-release", "npm publish", "uv publish", "cargo publish", "CARGO_REGISTRY_TOKEN", "PYPI_API_TOKEN", "NPM_TOKEN")
    for value in forbidden:
        if value in text:
            raise AssertionError(f"publishing capability present: {value}")
    uses = [step["uses"] for job in jobs.values() for step in job.get("steps", []) if "uses" in step]
    allowed_uses = required_pins
    if set(uses) != allowed_uses or any("@" not in use or len(use.rsplit("@", 1)[1]) != 40 for use in uses):
        raise AssertionError(f"action allowlist mismatch: {uses}")
    expected_build_rows = set(nv.ROWS)
    linux_rows = {entry["row"] for entry in jobs["build-linux"]["strategy"]["matrix"]["include"]}
    host_rows = {entry["row"] for entry in jobs["build-host"]["strategy"]["matrix"]["include"]}
    if linux_rows | host_rows != expected_build_rows or linux_rows & host_rows or len(linux_rows) != 4 or len(host_rows) != 3:
        raise AssertionError("seven-row build matrix changed")
    full = jobs["consume-full"]["strategy"]["matrix"]["include"]
    musl = jobs["consume-musl"]["strategy"]["matrix"]["include"]
    expected_full = {(row, version) for row in ("linux-x86_64", "linux-aarch64", "windows-x64", "macos-x86_64", "macos-aarch64") for version in ("3.10", "3.13")}
    expected_musl = {(row, version) for row in nv.MUSL_DIGESTS for version in ("3.10", "3.13")}
    if {(entry["row"], entry["python"]) for entry in full} != expected_full or len(full) != 10:
        raise AssertionError("full consumer matrix changed")
    if {(entry["row"], entry["python"]) for entry in musl} != expected_musl or len(musl) != 4:
        raise AssertionError("musl consumer matrix changed")
    recipe = "args: --release --out dist --manifest-path bindings/python/Cargo.toml"
    if text.count(recipe) != 2 or text.count("maturin-version: v1.11.5") != 2:
        raise AssertionError("release build recipe changed")
    if text.count("sccache: 'false'") != 2:
        raise AssertionError("tag-equivalent sccache setting changed")
    hook_text = LINUX_HOOK.read_text(encoding="utf-8")
    if "before-script-linux:" not in text or "native-linux-compiler-proof.sh" not in text or "rustc -vV" not in hook_text:
        raise AssertionError("in-container compiler proof missing")
    if "--print linker" in text or "--print linker" in hook_text or "--print\", \"linker" in HELPER.read_text(encoding="utf-8"):
        raise AssertionError("unsupported rustc linker query returned")
    for forbidden_hook in ("curl ", "wget ", "docker ", "git push", "publish", "GITHUB_TOKEN", "id-token"):
        if forbidden_hook in hook_text:
            raise AssertionError(f"Linux compiler hook crossed its bounded proof scope: {forbidden_hook}")
    if "--network none" not in text or "dst=/wheelhouse,readonly" not in text:
        raise AssertionError("offline read-only musl boundary missing")
    if "candidate/.native-evidence" in text or "mkdir -p candidate/native-validation-evidence" not in text:
        raise AssertionError("nonhidden host-precreated build evidence contract missing")
    if "uv self version --short" not in text or 'test "$(uv --version)"' in text:
        raise AssertionError("uv machine-readable version check missing")
    if "needs.preflight.result" not in text or "--needs-results" not in text:
        raise AssertionError("required job-result gate missing")
    helper = HELPER.read_text(encoding="utf-8")
    if helper.index("audit_wheel(wheelhouse, args.row, licenses)") > helper.index('"pip", "--isolated", "install", "--no-index"', helper.index("def command_consume_musl")):
        raise AssertionError("musl archive audit does not precede installation")


class ShaAndProcessTests(unittest.TestCase):
    def test_rejects_short_uppercase_and_shell_sha(self) -> None:
        for value in ("d58b69c", "D" * 40, "a" * 39 + ";", " " + "a" * 40):
            with self.assertRaises(SystemExit):
                nv.require_sha(value, "fixture")

    def test_rejects_wrong_source_and_harness_checkout(self) -> None:
        with self.assertRaises(SystemExit):
            nv.verify_checkout(ROOT, nv.CANDIDATE_SHA)
        with self.assertRaises(SystemExit):
            nv.verify_checkout(ROOT, "0" * 40)

    def test_nonzero_timeout_and_diagnostics_propagate(self) -> None:
        with self.assertRaises(SystemExit):
            nv.run([sys.executable, "-I", "-c", "raise SystemExit(7)"])
        with self.assertRaises(SystemExit):
            nv.run([sys.executable, "-I", "-c", "import time; time.sleep(2)"], timeout=1)
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "failure.log"
            code, timed_out = nv.run_logged(
                [sys.executable, "-I", "-c", "print('retained'); raise SystemExit(7)"],
                log, cwd=Path(tmp), timeout=10, env=nv.isolated_env(),
            )
            self.assertEqual(code, 7)
            self.assertFalse(timed_out)
            self.assertIn("retained", log.read_text())

    def test_pytest_environment_removes_all_injection(self) -> None:
        original = os.environ.copy()
        try:
            os.environ["PYTEST_PLUGINS"] = "hostile_plugin"
            os.environ["PYTEST_ADDOPTS"] = "--pwn"
            env = nv.isolated_env()
            self.assertNotIn("PYTEST_PLUGINS", env)
            self.assertNotIn("PYTEST_ADDOPTS", env)
            self.assertEqual(env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"], "1")
        finally:
            os.environ.clear()
            os.environ.update(original)

    def test_real_pinned_pytest_timeout_startup_is_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            venv = Path(tmp) / "venv"
            subprocess.check_call([sys.executable, "-I", "-m", "venv", str(venv)])
            python = nv.venv_python(venv)
            subprocess.check_call([str(python), "-I", "-m", "pip", "--isolated", "install", "-q", "pytest==9.0.3", "pytest-timeout==2.4.0"])
            env = nv.isolated_env()
            env["PYTEST_PLUGINS"] = "this_must_be_removed"
            env = nv.isolated_env()  # rebuild after hostile ambient fixture
            result = subprocess.run([str(python), "-I", "-B", "-m", "pytest", "-p", "pytest_timeout", "--help"], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("Plugin already registered", result.stdout)

    def test_uv_short_version_command_semantics(self) -> None:
        uv = shutil.which("uv")
        if uv is None:
            self.skipTest("uv is not locally installed")
        short = subprocess.check_output([uv, "self", "version", "--short"], text=True).strip()
        banner = subprocess.check_output([uv, "--version"], text=True).strip()
        self.assertRegex(short, r"^\d+\.\d+\.\d+$")
        self.assertTrue(banner.startswith("uv " + short))

    def test_compiler_env_and_ancestor_config_overrides_fail(self) -> None:
        original = os.environ.copy()
        try:
            os.environ["CARGO_BUILD_RUSTC"] = "/tmp/not-reviewed-rustc"
            with self.assertRaises(SystemExit):
                nv.reject_toolchain_overrides(ROOT)
        finally:
            os.environ.clear()
            os.environ.update(original)
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            original_cargo_home = os.environ.get("CARGO_HOME")
            original_toolchain = os.environ.get("RUSTUP_TOOLCHAIN")
            os.environ["CARGO_HOME"] = str(parent / "empty-cargo-home")
            os.environ["RUSTUP_TOOLCHAIN"] = "1.93.0"
            try:
                candidate = parent / "workspace/candidate"
                candidate.mkdir(parents=True)
                os.environ["CARGO_BUILD_TARGET"] = "aarch64-unknown-linux-gnu"
                nv.reject_toolchain_overrides(candidate, "aarch64-unknown-linux-gnu")
                with self.assertRaises(SystemExit):
                    nv.reject_toolchain_overrides(candidate, "x86_64-unknown-linux-gnu")
                os.environ.pop("CARGO_BUILD_TARGET")
                config = parent / "workspace/.cargo/config.toml"
                config.parent.mkdir()
                for hostile in (
                    '[build]\nrustc = "/tmp/not-reviewed-rustc"\n',
                    'build.rustc-wrapper = "/tmp/not-reviewed-wrapper"\n',
                    'build = { rustc = "/tmp/not-reviewed-rustc" }\n',
                    '[build]\n"rust\\u0063" = "/tmp/not-reviewed-rustc"\n',
                ):
                    config.write_text(hostile)
                    with self.subTest(hostile=hostile), self.assertRaises(SystemExit):
                        nv.effective_config_evidence(candidate)
                config.write_text('[target.aarch64-unknown-linux-gnu]\nlinker = "aarch64-linux-gnu-gcc"\nrustflags = ["-C", "target-feature=+crt-static"]\n')
                evidence = nv.effective_config_evidence(candidate)
                selected = [item for item in evidence if item["path"] == str(config)]
                self.assertEqual(len(selected), 1)
                self.assertIn("linker", selected[0]["reviewed_cross_settings"])
            finally:
                if original_cargo_home is None:
                    os.environ.pop("CARGO_HOME", None)
                else:
                    os.environ["CARGO_HOME"] = original_cargo_home
                if original_toolchain is None:
                    os.environ.pop("RUSTUP_TOOLCHAIN", None)
                else:
                    os.environ["RUSTUP_TOOLCHAIN"] = original_toolchain

    def test_modified_candidate_lock_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (
                ".github/workflows/release.yml", "Cargo.lock",
                "bindings/python/pyproject.toml", "bindings/python/Cargo.toml",
            ):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(subprocess.check_output(["git", "show", f"{nv.CANDIDATE_SHA}:{rel}"]))
            (root / "Cargo.lock").write_bytes((root / "Cargo.lock").read_bytes() + b"\n")
            original = nv.verify_checkout
            try:
                nv.verify_checkout = lambda *args, **kwargs: None
                with self.assertRaises(SystemExit):
                    nv.verify_candidate(root)
            finally:
                nv.verify_checkout = original

    def test_compiler_release_mismatch_fails(self) -> None:
        original = nv.run
        try:
            nv.run = lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, "rustc 1.92.0 (bad)\n", "")
            with self.assertRaises(SystemExit):
                nv.compiler_output(ROOT, "x86_64-unknown-linux-gnu")
        finally:
            nv.run = original

    def test_raw_compiler_proof_is_unique_ordered_and_substantive(self) -> None:
        row = "linux-x86_64"
        raw = raw_compiler_fixture(row)
        nv.parse_linux_compiler_raw(raw, row)
        mutations = (
            raw.replace("target=x86_64-unknown-linux-gnu\n", "target=wrong\ntarget=x86_64-unknown-linux-gnu\n", 1),
            raw.replace("c_compiler_begin\ngcc (GCC) 1.0 fixture\nc_compiler_end", "c_compiler_begin\nc_compiler_end"),
            raw.replace("rustc_vv_begin", "link_args_begin", 1),
            raw.replace("rustc_path=/toolchain/bin/rustc", "rustc_path=placeholder"),
            raw.replace("rustc_vv_begin", "cargo_config=BROKEN\nrustc_vv_begin"),
            raw.replace("rustc_vv_begin", f"cargo_config=/x|{'a' * 64}|target.x;\ncargo_config=/x|{'b' * 64}|target.x;\nrustc_vv_begin"),
            raw + "unexpected=record\n",
        )
        for mutated in mutations:
            with self.subTest(), self.assertRaises(SystemExit):
                nv.parse_linux_compiler_raw(mutated, row)

    def test_real_rust_193_tiny_link_args_probe(self) -> None:
        installed = subprocess.run(["rustup", "toolchain", "list"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if installed.returncode != 0 or "1.93.0" not in installed.stdout:
            self.skipTest("Rust 1.93.0 is not installed")
        original = os.environ.copy()
        try:
            os.environ["RUSTUP_TOOLCHAIN"] = "1.93.0"
            probe = nv.tiny_link_args(ROOT, "x86_64-unknown-linux-gnu")
            self.assertEqual(probe["returncode"], 0)
            self.assertIn("cc", probe["output"])
        finally:
            os.environ.clear()
            os.environ.update(original)

    def test_failed_or_unrecognized_tool_probes_fail(self) -> None:
        for probe in (
            {"returncode": 2, "output": "gcc (GCC) error: unsupported --version"},
            {"returncode": 0, "output": "error: unsupported argument --version"},
            {"returncode": 0, "output": ""},
        ):
            with self.subTest(probe=probe), self.assertRaises(SystemExit):
                nv.require_recognized_tool_probe(probe, "gnu-driver", "fixture")


class WheelAuditTests(unittest.TestCase):
    def audit(self, **kwargs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        wheelhouse = Path(tmp.name)
        make_wheel(wheelhouse, **kwargs)
        return nv.audit_wheel(wheelhouse, "linux-x86_64", ROOT)

    def test_valid_fixture_has_complete_record_and_hashes(self) -> None:
        report = self.audit()
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["binary"]["architecture"], "x86_64")
        self.assertEqual(report["license_status"], "canonical")

    def test_missing_and_extra_wheel_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                nv.one_wheel(Path(tmp), "linux-x86_64")
        with self.assertRaises(SystemExit):
            self.audit(extra_wheel=True)

    def test_wrong_version_abi_platform_and_architecture_fail(self) -> None:
        fixtures = (
            {"version": "0.8.4"},
            {"abi": "cp310"},
            {"platform_tag": "musllinux_1_2_x86_64"},
            {"machine": 183},
        )
        for fixture in fixtures:
            with self.subTest(fixture=fixture), self.assertRaises(SystemExit):
                self.audit(**fixture)

    def test_corrupt_record_and_license_fail(self) -> None:
        for fixture in ({"corrupt_record": "formualizer/__init__.py"}, {"corrupt_license": True}):
            with self.subTest(fixture=fixture), self.assertRaises(SystemExit):
                self.audit(**fixture)

    def test_raw_path_aliases_and_wrong_binary_family_fail(self) -> None:
        for raw in (r"a\..\escape", "C:/escape", "formualizer//__init__.py", "formualizer/./__init__.py", "/absolute"):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as tmp:
                archive_path = Path(tmp) / "bad.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(raw, b"x")
                with zipfile.ZipFile(archive_path) as archive, self.assertRaises(SystemExit):
                    nv.safe_zip_infos(archive)
        with tempfile.TemporaryDirectory() as tmp:
            wheelhouse = Path(tmp)
            make_wheel(wheelhouse, platform_tag="win_amd64")
            with self.assertRaises(SystemExit):
                nv.audit_wheel(wheelhouse, "windows-x64", ROOT)

    def test_casefold_destination_collision_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("Pkg/Name", b"x")
                archive.writestr("pkg/name", b"y")
            with zipfile.ZipFile(archive_path) as archive, self.assertRaises(SystemExit):
                nv.safe_zip_infos(archive)

    def test_traversal_and_symlink_payloads_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape", b"x")
            with zipfile.ZipFile(archive_path) as archive, self.assertRaises(SystemExit):
                nv.safe_zip_infos(archive)
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bad.zip"
            info = zipfile.ZipInfo("link")
            info.external_attr = 0o120777 << 16
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(info, b"target")
            with zipfile.ZipFile(archive_path) as archive, self.assertRaises(SystemExit):
                nv.safe_zip_infos(archive)


class IsolationAndInventoryTests(unittest.TestCase):
    def test_known_architecture_aliases_are_bounded(self) -> None:
        self.assertEqual(nv.normalize_machine("AMD64"), "x86_64")
        self.assertEqual(nv.normalize_machine("arm64"), "aarch64")
        self.assertEqual(nv.normalize_machine("aarch64"), "aarch64")
        with self.assertRaises(SystemExit):
            nv.normalize_machine("armv7l")

    def test_source_and_outside_venv_import_paths_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prefix = root / "venv"
            installed = prefix / "lib/site-packages/formualizer/__init__.py"
            source = root / "candidate/bindings/python/formualizer/__init__.py"
            with self.assertRaises(SystemExit):
                nv.require_installed_path(source, [prefix], [root / "candidate"], "wrapper")
            with self.assertRaises(SystemExit):
                nv.require_installed_path(installed, [prefix], [prefix / "lib"], "wrapper")
            nv.require_installed_path(installed, [prefix], [root / "candidate"], "wrapper")

    def test_remote_installed_paths_use_producer_platform_semantics(self) -> None:
        windows_root = r"D:\a\work\venv\Lib\site-packages"
        nv.require_recorded_installed_path(
            windows_root + r"\formualizer\__init__.py", [windows_root], "windows-x64", "wrapper"
        )
        with self.assertRaises(SystemExit):
            nv.require_recorded_installed_path(
                r"C:\other\formualizer\__init__.py", [windows_root], "windows-x64", "wrapper"
            )
        posix_root = "/tmp/venv/lib/python3.13/site-packages"
        nv.require_recorded_installed_path(posix_root + "/formualizer/__init__.py", [posix_root], "linux-x86_64", "wrapper")
        with self.assertRaises(SystemExit):
            nv.require_recorded_installed_path("relative/formualizer/__init__.py", [posix_root], "linux-x86_64", "wrapper")

    def test_test_staging_excludes_package_and_cargo_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp) / "stage"
            helper, config = nv.stage_tests(ROOT, staging)
            self.assertTrue(helper.is_file())
            self.assertTrue(config.is_file())
            self.assertFalse((staging / "formualizer").exists())
            self.assertEqual(list(staging.rglob("Cargo.toml")), [])
            self.assertTrue(list((staging / "tests").glob("test_*.py")))

    def smoke(self, root: Path, row: str, version: str, phase: str) -> dict:
        key = f"{row}-py{version}"
        if row == "windows-x64":
            site_text = rf"D:\a\_temp\native-consumer-work\{key}\venv\Lib\site-packages"
            package_path = site_text + r"\formualizer\__init__.py"
            native_path = site_text + r"\formualizer\formualizer_py.pyd"
        else:
            site = root / "venvs" / key / "site-packages"
            site_text = str(site)
            package_path = str(site / "formualizer/__init__.py")
            native_path = str(site / "formualizer/formualizer_py.so")
        return {
            "kind": "smoke", "status": "pass", "phase": phase,
            "consumer_row": key, "build_row": row, "candidate_sha": nv.CANDIDATE_SHA,
            "python": version + ".21", "implementation": "cpython",
            "machine": nv.ROWS[row]["arch"], "pointer_width": 64,
            "os_family": "linux", "libc": [nv.ROWS[row]["libc"], "fixture"],
            "libc_probe": "musl libc fixture" if row.startswith("musllinux") else "",
            "site_packages": [site_text],
            "package_path": package_path,
            "native_path": native_path,
            "wheel_sha256": "1" * 64, "native_sha256": "2" * 64,
            "package_sha256": "3" * 64,
            "installed_license_hashes": {"LICENSE-MIT": nv.MIT_SHA256, "LICENSE-APACHE": nv.APACHE_SHA256},
            "assertions": sorted(nv.SMOKE_ASSERTIONS), "xlsx_bytes": 1000,
        }

    def write_complete_inventory(self, root: Path) -> None:
        for index, row in enumerate(nv.ROWS, start=1):
            compiler = {
                "kind": "compiler", "status": "pass", "build_row": row,
                "target": nv.ROWS[row]["target"],
                "rustc_version": "rustc 1.93.0 (254b59607 2026-01-19)",
                "maturin_version": "maturin 1.11.5", "rustc_path": "/toolchain/bin/rustc",
                "target_libdir": f"/toolchain/lib/rustlib/{nv.ROWS[row]['target']}/lib", "linker": "cc", "linker_path": "/usr/bin/cc",
                "linker_source": "fixture", "c_compiler_path": "/usr/bin/cc",
                "runner_os": nv.BUILD_RUNNERS[row][0], "runner_arch": nv.BUILD_RUNNERS[row][1],
                "runner_image_os": "fixture", "runner_image_version": "1",
                "build_python": "python fixture", "effective_flags": {}, "cargo_configs": [],
            }
            compiler["link_args_probe"] = {"argv": ["rustc", "--print", "link-args"], "returncode": 0, "output": '"cc" fixture link args'}
            if row in nv.BUILD_IMAGES:
                raw = root / f"compiler-{row}.raw"
                raw.write_text(raw_compiler_fixture(row))
                _, configs, blocks = nv.parse_linux_compiler_raw(raw.read_text(), row)
                compiler.update({
                    "raw_sha256": nv.sha256_file(raw), "rustc_vv": blocks["rustc_vv"],
                    "cargo_configs": configs,
                    "link_args_probe": {"argv": ["rustc", "--print", "link-args"], "returncode": 0, "output": blocks["link_args"]},
                    "c_compiler_probe": {"argv": ["/usr/bin/cc", "--version"], "returncode": 0, "output": blocks["c_compiler"]},
                    "linker_probe": {"argv": ["/usr/bin/cc", "--version"], "returncode": 0, "output": blocks["linker_probe"]},
                    "build_python": {"status": "not-selected-by-validator", "executable": "", "version": ""},
                })
            else:
                compiler["rustc_vv"] = compiler["rustc_version"]
                if row == "windows-x64":
                    compiler["linker"] = "link.exe"
                    compiler["linker_path"] = r"C:\Program Files\Microsoft Visual Studio\VC\bin\link.exe"
                    compiler["c_compiler_path"] = r"C:\Program Files\Microsoft Visual Studio\VC\bin\cl.exe"
                    compiler["link_args_probe"]["output"] = '"link.exe" fixture link args'
                    compiler["c_compiler_probe"] = {"returncode": 0, "output": "Microsoft (R) C/C++ Optimizing Compiler", "argv": [compiler["c_compiler_path"], "/?"]}
                    compiler["linker_probe"] = {"returncode": 0, "output": "Microsoft (R) Incremental Linker", "argv": [compiler["linker_path"], "/?"]}
                else:
                    compiler["c_compiler_probe"] = {"returncode": 0, "output": "Apple clang version fixture"}
                    compiler["linker_probe"] = {"returncode": 0, "output": "Apple clang version fixture"}
            compiler_path = root / f"compiler-{row}.json"
            compiler_path.write_text(json.dumps(compiler))
            native_path = root / f"native-inspection-{row}.txt"
            native_path.write_text({"ELF": "ELF Dynamic section", "Mach-O": "compatibility version", "PE": "Format: COFF"}[nv.ROWS[row]["binary"]])
            builder_path = root / f"builder-{row}.txt"
            if row in nv.BUILD_IMAGES:
                builder_path.write_text(f"runner_image_os=fixture\nrunner_image_version=1\nselected_build_image={nv.BUILD_IMAGES[row]}\nrepo_digests=[x@sha256:{'4' * 64}]")
            else:
                builder_path.write_text("runner_image_os=fixture\nrunner_image_version=1\n")
            (root / f"build-{row}.json").write_text(json.dumps({
                "kind": "build", "status": "pass", "build_row": row,
                "candidate_sha": nv.CANDIDATE_SHA, "candidate_tree": nv.CANDIDATE_TREE,
                "workflow_sha": "a" * 40, "run_id": "99", "run_attempt": "1",
                "release_recipe_hash": nv.RELEASE_SHA256, "cargo_lock_hash": nv.LOCK_SHA256,
                "action_commit": "e83996d129638aa358a18fbd1dfb82f0b0fb5d3b",
                "resolved_target": nv.ROWS[row]["target"],
                "upload_output_artifact_id": str(100 + index),
                "upload_output_artifact_digest": "5" * 64,
                "upload_identity_scope": "syntax-captured action outputs; fixture",
                "wheel_sha256": "1" * 64, "native_sha256": "2" * 64,
                "wrapper_sha256": "3" * 64,
                "compiler_filename": compiler_path.name, "compiler_sha256": nv.sha256_file(compiler_path),
                "native_inspection_filename": native_path.name, "native_inspection_sha256": nv.sha256_file(native_path),
                "builder_filename": builder_path.name, "builder_sha256": nv.sha256_file(builder_path),
            }))
        full_rows = ("linux-x86_64", "linux-aarch64", "windows-x64", "macos-x86_64", "macos-aarch64")
        for row in full_rows:
            for version in ("3.10", "3.13"):
                key = f"{row}-py{version}"
                pre = root / f"smoke-pre-{key}.json"
                post = root / f"smoke-post-{key}.json"
                pre.write_text(json.dumps(self.smoke(root, row, version, "pre-suite")))
                post.write_text(json.dumps(self.smoke(root, row, version, "post-suite")))
                pre_log = root / f"smoke-pre-{key}.log"
                post_log = root / f"smoke-post-{key}.log"
                pre_log.write_text("pre smoke passed\n")
                post_log.write_text("post smoke passed\n")
                junit = root / f"pytest-{key}.xml"
                junit.write_text('<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase classname="x" name="y"/></testsuite>')
                log = root / f"pytest-{key}.log"
                log.write_text("collected 1 item\n1 passed\n")
                provisioning = root / f"python-provisioning-{key}.txt"
                provisioning_text = f"cpython {version} fixture\n"
                if key == "macos-aarch64-py3.10":
                    provisioning_text += "uv 0.12.10\nc2ddcefee6ae51286001dc22320434676adcc89362330823b409eac51a101a4b\n"
                provisioning.write_text(provisioning_text)
                counts = {"tests": 1, "failures": 0, "errors": 0, "skipped": 0, "testcases": 1, "passed": 1, "xfailed": 0}
                (root / f"consumer-{key}.json").write_text(json.dumps({
                    "kind": "consumer", "level": "full-suite", "status": "pass",
                    "consumer_row": key, "build_row": row, "wheel_sha256": "1" * 64,
                    "candidate_sha": nv.CANDIDATE_SHA, "workflow_sha": "a" * 40,
                    "run_id": "99", "run_attempt": "1", "pytest_counts": counts,
                    "collected": 1, "deselected": 0,
                    "smoke_pre_sha256": nv.sha256_file(pre), "smoke_post_sha256": nv.sha256_file(post),
                    "smoke_pre_log_sha256": nv.sha256_file(pre_log), "smoke_post_log_sha256": nv.sha256_file(post_log),
                    "pytest_junit_sha256": nv.sha256_file(junit), "pytest_output_sha256": nv.sha256_file(log),
                    "provisioning_filename": provisioning.name, "provisioning_sha256": nv.sha256_file(provisioning),
                }))
        for row in nv.MUSL_DIGESTS:
            for version in ("3.10", "3.13"):
                key = f"{row}-py{version}"
                smoke = root / f"smoke-{key}.json"
                smoke.write_text(json.dumps(self.smoke(root, row, version, "musl")))
                container = root / f"container-{key}.txt"
                container.write_text(f"repo@{nv.MUSL_DIGESTS[row]}")
                (root / f"consumer-{key}.json").write_text(json.dumps({
                    "kind": "consumer", "level": "bounded-musl-smoke", "status": "pass",
                    "consumer_row": key, "build_row": row, "wheel_sha256": "1" * 64,
                    "candidate_sha": nv.CANDIDATE_SHA, "workflow_sha": "a" * 40,
                    "run_id": "99", "run_attempt": "1",
                    "container_image": f"quay.io/example@{nv.MUSL_DIGESTS[row]}",
                    "container_digest": nv.MUSL_DIGESTS[row],
                    "container_evidence_sha256": nv.sha256_file(container),
                    "smoke_sha256": nv.sha256_file(smoke),
                }))

    def aggregate(self, root: Path, needs: dict[str, str] | None = None) -> None:
        args = type("Args", (), {
            "evidence": str(root), "workflow_sha": "a" * 40,
            "run_id": "99", "run_attempt": "1",
            "needs_results": json.dumps(needs or {name: "success" for name in ("preflight", "build-linux", "build-host", "consume-full", "consume-musl")}),
            "output": str(root / "summary.txt"),
        })()
        nv.command_aggregate(args)

    def test_complete_inventory_passes_but_missing_or_mismatched_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_complete_inventory(root)
            self.aggregate(root)
            (root / "consumer-linux-x86_64-py3.10.json").unlink()
            with self.assertRaises(SystemExit):
                self.aggregate(root)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_complete_inventory(root)
            path = root / "consumer-linux-x86_64-py3.10.json"
            data = json.loads(path.read_text())
            data["wheel_sha256"] = "2" * 64
            path.write_text(json.dumps(data))
            with self.assertRaises(SystemExit):
                self.aggregate(root)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_complete_inventory(root)
            (root / "compiler-linux-x86_64.json").write_text("{corrupt")
            with self.assertRaises(SystemExit):
                self.aggregate(root)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_complete_inventory(root)
            needs = {name: "success" for name in ("preflight", "build-linux", "build-host", "consume-full", "consume-musl")}
            needs["build-host"] = "failure"
            with self.assertRaises(SystemExit):
                self.aggregate(root, needs)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_complete_inventory(root)
            smoke = root / "smoke-post-linux-x86_64-py3.13.json"
            data = json.loads(smoke.read_text())
            data["implementation"] = "pypy"
            data["assertions"] = []
            smoke.write_text(json.dumps(data))
            report = root / "consumer-linux-x86_64-py3.13.json"
            report_data = json.loads(report.read_text())
            report_data["smoke_post_sha256"] = nv.sha256_file(smoke)
            report.write_text(json.dumps(report_data))
            with self.assertRaises(SystemExit):
                self.aggregate(root)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_complete_inventory(root)
            (root / "pytest-linux-aarch64-py3.10.xml").unlink()
            with self.assertRaises(SystemExit):
                self.aggregate(root)

    def test_aggregate_reparses_raw_proof_after_all_hashes_are_updated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_complete_inventory(root)
            raw = root / "compiler-linux-x86_64.raw"
            raw.write_text(raw.read_text().replace("rustc_path=/toolchain/bin/rustc", "rustc_path=placeholder"))
            compiler_path = root / "compiler-linux-x86_64.json"
            compiler = json.loads(compiler_path.read_text())
            compiler["raw_sha256"] = nv.sha256_file(raw)
            compiler_path.write_text(json.dumps(compiler))
            build_path = root / "build-linux-x86_64.json"
            build = json.loads(build_path.read_text())
            build["compiler_sha256"] = nv.sha256_file(compiler_path)
            build_path.write_text(json.dumps(build))
            with self.assertRaises(SystemExit):
                self.aggregate(root)

    def test_zero_failed_and_skipped_pytest_inventories_fail_closed(self) -> None:
        for attrs in (
            'tests="0" failures="0" errors="0" skipped="0"',
            'tests="2" failures="1" errors="0" skipped="0"',
            'tests="2" failures="0" errors="0" skipped="1"',
        ):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "junit.xml"
                path.write_text(f"<testsuite {attrs}></testsuite>")
                with self.assertRaises(SystemExit):
                    nv.junit_counts(path)


class WorkflowContractTests(unittest.TestCase):
    def test_shell_config_scanner_rejects_inline_and_escaped_compiler_keys(self) -> None:
        for hostile in (
            'build = { rustc = "/tmp/unreviewed-rustc" }\n',
            '[build]\n"rust\\u0063" = "/tmp/unreviewed-rustc"\n',
        ):
            with self.subTest(hostile=hostile), tempfile.TemporaryDirectory() as tmp:
                candidate = Path(tmp) / "candidate"
                (candidate / ".cargo").mkdir(parents=True)
                (candidate / "native-validation-evidence").mkdir()
                (candidate / ".cargo/config.toml").write_text(hostile)
                env = os.environ.copy()
                env["RUSTUP_TOOLCHAIN"] = "1.93.0"
                env["CARGO_HOME"] = str(Path(tmp) / "empty-cargo-home")
                result = subprocess.run(
                    ["bash", str(LINUX_HOOK), "linux-x86_64", "x86_64-unknown-linux-gnu", "native-validation-evidence/compiler-linux-x86_64.raw"],
                    cwd=candidate, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("unsupported Cargo config", result.stdout)

    def test_actual_extracted_linux_hook_and_source_are_bash_syntax_valid(self) -> None:
        workflow = parse_workflow(WORKFLOW.read_text(encoding="utf-8"))
        step = next(step for step in workflow["jobs"]["build-linux"]["steps"] if "PyO3/maturin-action@" in step.get("uses", ""))
        hook = step["with"]["before-script-linux"]
        hook = hook.replace("${{ matrix.row }}", "linux-x86_64").replace("${{ matrix.resolved_target }}", "x86_64-unknown-linux-gnu")
        parsed = subprocess.run(["bash", "-n"], input=hook, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(parsed.returncode, 0, parsed.stdout)
        parsed = subprocess.run(["bash", "-n", str(LINUX_HOOK)], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(parsed.returncode, 0, parsed.stdout)

    def test_manual_nonpublishing_exact_recipe_and_pins(self) -> None:
        assert_workflow_contract(WORKFLOW.read_text(encoding="utf-8"))

    def test_build_contract_matches_frozen_release_workflow(self) -> None:
        release = subprocess.check_output(
            ["git", "show", f"{nv.CANDIDATE_SHA}:.github/workflows/release.yml"]
        )
        self.assertEqual(hashlib.sha256(release).hexdigest(), nv.RELEASE_SHA256)
        text = release.decode("utf-8")
        recipe = "args: --release --out dist --manifest-path bindings/python/Cargo.toml"
        self.assertEqual(text.count(recipe), 4)
        self.assertEqual(text.count("maturin-version: v1.11.5"), 5)
        self.assertIn("uses: actions/checkout@v6", text)
        self.assertIn("uses: actions/setup-python@v6", text)
        self.assertIn("uses: PyO3/maturin-action@v1", text)
        self.assertIn("sccache: ${{ !startsWith(github.ref, 'refs/tags/') }}", text)
        for target in ("x86_64", "aarch64", "x64"):
            self.assertIn(f"target: {target}", text)
        for runner in ("ubuntu-22.04", "windows-latest", "macos-latest"):
            self.assertIn(runner, text)

    def test_security_and_provenance_negative_fixtures(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            text.replace("  workflow_dispatch:", "  push:"),
            text.replace("  workflow_dispatch:\n", "  workflow_dispatch:\n  schedule:\n    - cron: '0 0 * * *'\n", 1),
            text.replace("  contents: read", "  contents: write"),
            text.replace("permissions:\n  contents: read", "permissions:\n  contents: read\n  id-token: write"),
            text.replace("    runs-on: ubuntu-22.04", "    runs-on: ubuntu-22.04\n    permissions:\n      actions: write", 1),
            text.replace("    steps:\n", "    steps:\n      - uses: evil/example@0000000000000000000000000000000000000000\n", 1),
            text.replace("          - row: linux-x86_64", "          - row: invented-row\n            target: x86_64\n          - row: linux-x86_64", 1),
            text.replace("sccache: 'false'", "sccache: 'true'", 1),
            text.replace("PyO3/maturin-action@e83996d129638aa358a18fbd1dfb82f0b0fb5d3b", "PyO3/maturin-action@v1", 1),
            text + "\n# cargo publish\n",
            text.replace("--network none", "--network bridge"),
        )
        for mutated in mutations:
            with self.subTest(), self.assertRaises(AssertionError):
                assert_workflow_contract(mutated)

    def test_no_downstream_completion_publisher_trigger_exists(self) -> None:
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            if path == WORKFLOW:
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("workflow_run:", text, path.name)
            self.assertNotIn("native-release-validation", text, path.name)


if __name__ == "__main__":
    unittest.main()
