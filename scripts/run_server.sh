#!/bin/bash
set -euo pipefail

ROOT="$BUILD_WORKSPACE_DIRECTORY"
cd "$ROOT"

VALID_FLAGS=(
  "unused"
)

VALID_FLAGS_NO_ARGS=(
  "use_azure_auth"
)


# This argument-parsing monstrosity brought to you by some random GitHub Gist:
# https://gist.github.com/magnetikonline/22c1eb412daa350eeceee76c97519da8
OPTS=$(getopt \
  --longoptions "$(printf "%s:," "${VALID_FLAGS[@]}")" \
  --longoptions "$(printf "%s," "${VALID_FLAGS_NO_ARGS[@]}")" \
  --name "$(basename "$0")" \
  --options "" \
  -- "$@"
)

if ! [ -x "$(command -v sops)" ]; then
  echo 'Error: sops is not installed.' >&2
  exit 1
fi

TMP_CONFIG_DIR="$(mktemp -d -t credsrv-local-XXXXXXXXX)"
function cleanup {
  rm -rf "$TMP_CONFIG_DIR"
}
trap cleanup EXIT
TMP_ALLOWLIST_FILE="${TMP_CONFIG_DIR}/local.json"
TMP_CONFIG_FILE="${TMP_CONFIG_DIR}/local.conf"
sops -d "$ROOT/cmd/server/configs/allowlists/local.enc.json" > "$TMP_ALLOWLIST_FILE"
cp "$ROOT/cmd/server/configs/local.conf" "$TMP_CONFIG_FILE"
printf "\nallowlist_file %s\n" "$TMP_ALLOWLIST_FILE" >> "$TMP_CONFIG_FILE"

eval set --$OPTS

declare -a FLAGS=(
  "--config=$TMP_CONFIG_FILE"
)
while [ ! $# -eq 0 ]
do
  case "$1" in
    --use_azure_auth)
      FLAGS+=("--use_local_jwts=false")
      ;;
  esac
  shift
done

bazel run --run_under="cd $ROOT && " //cmd/server -- "${FLAGS[@]}"
