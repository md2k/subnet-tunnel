#!/usr/bin/env bash
# release.sh — cut a release of subtun in one command.
#
# A release is a GitHub RELEASE with cross-OS `subtun` binaries + checksums.txt.
# Every binary embeds the Linux agents (amd64, arm64) it uploads into targets.
#
# What it does, in order (all LOCAL building happens BEFORE any remote mutation,
# so a failed build never leaves an orphaned tag):
#   preflight → build Linux agents → build CLI matrix (6 targets) + checksums →
#   create+push tag → gh release create (Latest).
#
# Usage:
#   scripts/release.sh v0.1.0                       # tag + binaries + GH release
#   scripts/release.sh v0.1.0 --notes-file X.md    # curated changelog (else auto-generated from PRs)
#   scripts/release.sh v0.1.0 --dry-run            # build everything, but DON'T push tag / create release
#
# gh does not follow git's per-directory identity. If the active gh account
# can't see this repo, run with a token for one that can:
#   GH_TOKEN=$(gh auth token -u <user>) scripts/release.sh v0.1.0
#
# Requirements: git, go, gh (authenticated), tar, zip, shasum.
set -euo pipefail

# ---- constants ---------------------------------------------------------------
VERSION_PKG="github.com/md2k/subnet-tunnel/internal/version"
AGENT_DIR="internal/agentbin/dist"
AGENT_ARCHES=(amd64 arm64)
PLATFORMS=(darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64)

# ---- logging -----------------------------------------------------------------
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- args --------------------------------------------------------------------
VERSION=""
DRY_RUN=false
NOTES_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=true; shift ;;
    --notes-file) NOTES_FILE="${2:-}"; shift 2 ;;
    -h|--help)    sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; s/^set -euo.*//'; exit 0 ;;
    -*)           die "unknown flag: $1 (see --help)" ;;
    *)            [[ -z "$VERSION" ]] || die "unexpected extra argument: $1"; VERSION="$1"; shift ;;
  esac
done
[[ -n "$VERSION" ]] || die "version required, e.g. scripts/release.sh v0.1.0"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must be vMAJOR.MINOR.PATCH (got: $VERSION)"
[[ -z "$NOTES_FILE" || -f "$NOTES_FILE" ]] || die "notes file not found: $NOTES_FILE"

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not in a git repository"
cd "$REPO_ROOT"
REL_DIR="$REPO_ROOT/build/release"   # under /build/ which is gitignored

# ---- preflight ---------------------------------------------------------------
log "Preflight for $VERSION $($DRY_RUN && echo '(dry-run)')"
for t in git go tar zip shasum; do command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"; done
if ! $DRY_RUN; then
  command -v gh >/dev/null 2>&1 || die "missing required tool: gh"
  gh auth status >/dev/null 2>&1 || die "gh is not authenticated (run: gh auth login)"
  # Without this, a gh account that can't see the repo makes every
  # "does it exist" check below pass, and the release fails after the tag push.
  gh repo view --json name >/dev/null 2>&1 \
    || die "gh can't access this repo with the active account (try: GH_TOKEN=\$(gh auth token -u <user>) ...)"
  [[ -z "$(git status --porcelain)" ]] || die "working tree not clean — commit or stash first"
  branch="$(git rev-parse --abbrev-ref HEAD)"
  [[ "$branch" == "main" ]] || die "releases must be cut from main (currently on: $branch)"
  git fetch origin --quiet
  [[ "$(git rev-parse @)" == "$(git rev-parse '@{u}')" ]] || die "main is not in sync with origin/main — pull/push first"
  git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null 2>&1 && die "tag $VERSION already exists locally"
  git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1 && die "tag $VERSION already exists on origin"
  gh release view "$VERSION" >/dev/null 2>&1 && die "GitHub release $VERSION already exists"
  log "Preflight OK — on main, in sync, tag/release $VERSION is free"
else
  warn "dry-run: skipping git/gh preflight (branch, sync, tag checks)"
fi

# ---- version stamp (from $VERSION, not git describe — correct even in dry-run)
GIT_SHA="$(git rev-parse --short HEAD)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP="-X ${VERSION_PKG}.GitSHA=${GIT_SHA} -X ${VERSION_PKG}.BuildDate=${BUILD_DATE} -X ${VERSION_PKG}.Version=${VERSION}"
# -trimpath + -s -w: smaller, reproducible, no build-machine path leak.
LDFLAGS="-s -w ${STAMP}"

# ---- build Linux agents (embedded into every CLI binary) ---------------------
log "Building agents (${AGENT_ARCHES[*]}) → $AGENT_DIR"
for arch in "${AGENT_ARCHES[@]}"; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" \
    -o "$AGENT_DIR/subtun-agent-linux-$arch" ./cmd/subtun-agent
done

# ---- build CLI matrix (local) ------------------------------------------------
log "Building CLI matrix (${#PLATFORMS[@]} targets) → $REL_DIR"
rm -rf "$REL_DIR"; mkdir -p "$REL_DIR"
for platform in "${PLATFORMS[@]}"; do
  os="${platform%/*}"; arch="${platform#*/}"
  bin="subtun"; [[ "$os" == "windows" ]] && bin="subtun.exe"
  stage="$REL_DIR/.stage/${os}_${arch}"   # inside build/, never a system temp dir
  mkdir -p "$stage"
  log "  $os/$arch"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$stage/$bin" ./cmd/subtun
  if [[ "$os" == "windows" ]]; then
    ( cd "$stage" && zip -q "$REL_DIR/subtun_${os}_${arch}.zip" "$bin" )
  else
    tar -czf "$REL_DIR/subtun_${os}_${arch}.tar.gz" -C "$stage" "$bin"
  fi
done
rm -rf "$REL_DIR/.stage"
( cd "$REL_DIR" && shasum -a 256 subtun_* > checksums.txt )
log "CLI artifacts:"; ( cd "$REL_DIR" && ls -1 )

# ---- remote mutations (skipped in dry-run) -----------------------------------
if $DRY_RUN; then
  warn "DRY RUN — no tag pushed, no release created."
  log  "Would push tag:      $VERSION"
  if [[ -n "$NOTES_FILE" ]]; then log "Would create release $VERSION with notes from $NOTES_FILE + $(cd "$REL_DIR" && ls | wc -l | tr -d ' ') assets";
  else log "Would create release $VERSION (--generate-notes) + $(cd "$REL_DIR" && ls | wc -l | tr -d ' ') assets"; fi
  log "Dry run complete. Inspect artifacts in $REL_DIR"
  exit 0
fi

log "Creating + pushing tag $VERSION"
git tag -a "$VERSION" -m "$VERSION"
git push origin "$VERSION"

log "Creating GitHub release $VERSION"
notes_args=(--generate-notes)
[[ -n "$NOTES_FILE" ]] && notes_args=(--notes-file "$NOTES_FILE")
gh release create "$VERSION" \
  "$REL_DIR"/subtun_*.tar.gz "$REL_DIR"/subtun_*.zip "$REL_DIR/checksums.txt" \
  --title "$VERSION" --latest "${notes_args[@]}"

log "Release $VERSION done."
log "  GH release: $(gh release view "$VERSION" --json url --jq .url 2>/dev/null || echo 'created')"
