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

eval set --$OPTS

declare -a FLAGS=(
  "--config=cmd/server/configs/local.conf"
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
