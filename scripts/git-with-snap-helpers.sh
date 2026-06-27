#!/bin/sh

set -eu

export GIT_EXEC_PATH="/snap/codex/34/usr/lib/git-core"
exec /snap/codex/34/usr/bin/git "$@"
