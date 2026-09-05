#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: native-linux-compiler-proof.sh ROW TARGET OUTPUT" >&2
  exit 2
fi
row=$1
target=$2
evidence=$3
case "$row:$target" in
  linux-x86_64:x86_64-unknown-linux-gnu|linux-aarch64:aarch64-unknown-linux-gnu|musllinux-x86_64:x86_64-unknown-linux-musl|musllinux-aarch64:aarch64-unknown-linux-musl) ;;
  *) echo "unreviewed Linux row/target: $row:$target" >&2; exit 1 ;;
esac
[[ -d native-validation-evidence && $evidence == native-validation-evidence/compiler-"$row".raw ]]

for key in CARGO RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR; do
  [[ -z ${!key-} ]] || { echo "forbidden compiler/build override: $key" >&2; exit 1; }
done
[[ ${RUSTUP_TOOLCHAIN-} == 1.93.0 ]]
cargo_build_target=${CARGO_BUILD_TARGET-}
[[ -z $cargo_build_target || $cargo_build_target == "$target" ]] || {
  echo "CARGO_BUILD_TARGET does not match resolved target" >&2
  exit 1
}
target_key=${target^^}
target_key=${target_key//-/_}
linker_env=CARGO_TARGET_${target_key}_LINKER
rustflags_env=CARGO_TARGET_${target_key}_RUSTFLAGS
linker=${!linker_env-}
linker_source=$linker_env
reviewed_target_rustflags=${!rustflags_env-}

config_records=$(mktemp)
probe_output=$(mktemp)
link_output=$(mktemp)
cleanup() {
  rm -f "$config_records" "$probe_output" "$link_output" "/tmp/native-validator-link-probe-$$"
}
trap cleanup EXIT

config_linker=
config_linker_source=
scan_config() {
  local config=$1 active_target= line trimmed key raw_value value hash settings=
  [[ -f $config ]] || return 0
  [[ $config != *'|'* && $config != *$'\n'* ]] || { echo "unsupported Cargo config path" >&2; exit 1; }
  while IFS= read -r line || [[ -n $line ]]; do
    trimmed=${line#"${line%%[![:space:]]*}"}
    trimmed=${trimmed%"${trimmed##*[![:space:]]}"}
    [[ -z $trimmed || ${trimmed:0:1} == '#' ]] && continue
    [[ $trimmed != *'\\'* && $trimmed != *'{'* && $trimmed != *'}'* && $trimmed != *'|'* && $trimmed != *';'* ]] || {
      echo "unsupported Cargo config syntax: $config" >&2
      exit 1
    }
    if [[ ${trimmed:0:1} == '[' ]]; then
      if [[ $trimmed =~ ^\[target\.([a-z0-9][a-z0-9_-]*)\]$ ]]; then
        active_target=${BASH_REMATCH[1]}
        settings+="target.$active_target;"
        continue
      fi
      echo "unsupported Cargo config section: $config" >&2
      exit 1
    fi
    [[ -n $active_target && $trimmed == *'='* ]] || { echo "unsupported Cargo config record: $config" >&2; exit 1; }
    key=${trimmed%%=*}
    key=${key%"${key##*[![:space:]]}"}
    raw_value=${trimmed#*=}
    raw_value=${raw_value#"${raw_value%%[![:space:]]*}"}
    case $key in
      linker|runner)
        if [[ $raw_value =~ ^\"([^\"\\]+)\"$ ]]; then
          value=${BASH_REMATCH[1]}
        else
          echo "unsupported Cargo target value: $config:$key" >&2
          exit 1
        fi
        ;;
      rustflags)
        if [[ $raw_value =~ ^\"[^\"\\]*\"$ || $raw_value =~ ^\[[[:space:]]*\"[^\"\\]*\"([[:space:]]*,[[:space:]]*\"[^\"\\]*\")*[[:space:]]*\]$ ]]; then
          value=$raw_value
        else
          echo "unsupported Cargo target value: $config:$key" >&2
          exit 1
        fi
        ;;
      *) echo "unsupported Cargo target key: $config:$key" >&2; exit 1 ;;
    esac
    [[ $settings != *"target.$active_target:$key="* ]] || { echo "duplicate Cargo target key: $config:$key" >&2; exit 1; }
    settings+="target.$active_target:$key=$value;"
    if [[ $active_target == "$target" && $key == linker && -z $config_linker ]]; then
      config_linker=$value
      config_linker_source=$config
    fi
  done < "$config"
  hash=$(sha256sum "$config")
  hash=${hash%% *}
  printf 'cargo_config=%s|%s|%s\n' "$config" "$hash" "$settings" >> "$config_records"
}

scan_directory() {
  local directory=$1
  if [[ -f $directory/.cargo/config && -f $directory/.cargo/config.toml ]]; then
    echo "ambiguous Cargo config/config.toml pair: $directory/.cargo" >&2
    exit 1
  fi
  scan_config "$directory/.cargo/config"
  scan_config "$directory/.cargo/config.toml"
}

directory=$PWD
while :; do
  scan_directory "$directory"
  [[ $directory == / ]] && break
  directory=$(dirname "$directory")
done
cargo_home=${CARGO_HOME:-$HOME/.cargo}
if [[ -f $cargo_home/config && -f $cargo_home/config.toml ]]; then
  echo "ambiguous Cargo home config/config.toml pair" >&2
  exit 1
fi
scan_config "$cargo_home/config"
scan_config "$cargo_home/config.toml"
if [[ -z $linker && -n $config_linker ]]; then
  linker=$config_linker
  linker_source=$config_linker_source
fi
if [[ -z $linker ]]; then
  linker=cc
  linker_source=rustc-link-args-target-default
fi
[[ $linker != *$'\n'* && $linker != *$'\r'* ]]
linker_path=$(command -v -- "$linker")
[[ -x $linker_path ]]

[[ $(rustc --version) == 'rustc 1.93.0 (254b59607 2026-01-19)' ]]
[[ $(maturin --version) == 'maturin 1.11.5' ]]
target_libdir=$(rustc --print target-libdir --target "$target")
[[ -d $target_libdir ]]
rustc_probe=(rustc --crate-name native_validator_linker_probe --target "$target")
if [[ $linker_source != rustc-link-args-target-default ]]; then
  rustc_probe+=(-C "linker=$linker_path")
fi
rustc_probe+=(--print link-args -o "/tmp/native-validator-link-probe-$$" -)
printf 'fn main() {}\n' | "${rustc_probe[@]}" > "$link_output" 2>&1
[[ -s $link_output ]]
linker_name=${linker##*/}
grep -Fqi -- "$linker_name" "$link_output" || { echo "rustc link-args did not select $linker" >&2; exit 1; }
"$linker_path" --version > "$probe_output" 2>&1
[[ -s $probe_output ]]
grep -Eiq '^([[:alnum:]_+./-]*(cc|gcc)) \([^)]+\) [0-9]|^(Apple )?clang version [0-9]' "$probe_output" || { echo "unrecognized target compiler/linker banner" >&2; exit 1; }

{
  printf 'format=native-compiler-proof-v2\n'
  printf 'build_row=%s\n' "$row"
  printf 'target=%s\n' "$target"
  printf 'config_scan=pass\n'
  printf 'cargo_build_target=%s\n' "$cargo_build_target"
  printf 'target_rustflags=%s\n' "$reviewed_target_rustflags"
  printf 'rustc_version=%s\n' "$(rustc --version)"
  printf 'rustc_path=%s\n' "$(rustup which rustc)"
  printf 'target_libdir=%s\n' "$target_libdir"
  printf 'linker=%s\n' "$linker"
  printf 'linker_path=%s\n' "$linker_path"
  printf 'linker_source=%s\n' "$linker_source"
  printf 'c_compiler_path=%s\n' "$linker_path"
  printf 'maturin_version=%s\n' "$(maturin --version)"
  printf 'build_python_status=not-selected-by-validator\n'
  printf 'build_python_executable=\n'
  printf 'build_python_version=\n'
  printf 'cc=%s\ncxx=%s\ncflags=%s\ncppflags=%s\ncxxflags=%s\nldflags=%s\narchflags=%s\nmacosx_deployment_target=%s\nsdkroot=%s\n' "${CC-}" "${CXX-}" "${CFLAGS-}" "${CPPFLAGS-}" "${CXXFLAGS-}" "${LDFLAGS-}" "${ARCHFLAGS-}" "${MACOSX_DEPLOYMENT_TARGET-}" "${SDKROOT-}"
  cat "$config_records"
  echo rustc_vv_begin
  rustc -vV
  cargo -V
  rustup show active-toolchain
  rustup target list --installed
  uname -a
  echo rustc_vv_end
  echo link_args_begin
  cat "$link_output"
  echo link_args_end
  echo c_compiler_begin
  cat "$probe_output"
  echo c_compiler_end
  echo linker_probe_begin
  cat "$probe_output"
  echo linker_probe_end
} > "$evidence"
