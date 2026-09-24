#!/bin/sh
#
# Installs the KMG security git hooks into a repository.
#
#   ./tools/git-hooks/install.sh [path-to-repo]
#
# Defaults to the repository this script lives in. Existing hooks are backed up
# as <hook>.kmg-backup.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET_REPO=${1:-$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)}

HOOKS_DIR=$(git -C "$TARGET_REPO" rev-parse --git-path hooks)
case "$HOOKS_DIR" in
  /*) ;;
  *) HOOKS_DIR="$TARGET_REPO/$HOOKS_DIR" ;;
esac

mkdir -p "$HOOKS_DIR"

for hook in pre-push pre-commit; do
  if [ -f "$HOOKS_DIR/$hook" ] && ! grep -q "KMG AI Security Agent" "$HOOKS_DIR/$hook" 2>/dev/null; then
    cp "$HOOKS_DIR/$hook" "$HOOKS_DIR/$hook.kmg-backup"
    echo "  saved existing $hook -> $hook.kmg-backup"
  fi
  cp "$SCRIPT_DIR/$hook" "$HOOKS_DIR/$hook"
  chmod +x "$HOOKS_DIR/$hook"
  echo "  installed $hook"
done

# The hooks look for kmg-guard.mjs at <repo>/tools/git-hooks/ by default. When
# the guard lives in another checkout (the normal case for a target project),
# record its absolute path in that repository's git config; the hooks read it.
if [ ! -f "$TARGET_REPO/tools/git-hooks/kmg-guard.mjs" ]; then
  git -C "$TARGET_REPO" config --local kmg.guardpath "$SCRIPT_DIR/kmg-guard.mjs"
  echo "  guard path pinned: kmg.guardpath=$SCRIPT_DIR/kmg-guard.mjs"
fi

echo ""
echo "KMG security hooks installed into: $HOOKS_DIR"
echo ""
echo "Now set your KMG session token (copy it from the KMG web UI):"
echo "  git -C \"$TARGET_REPO\" config --local kmg.token   <TOKEN>"
echo "  git -C \"$TARGET_REPO\" config --local kmg.apiurl  http://localhost:3000/api"
echo ""
