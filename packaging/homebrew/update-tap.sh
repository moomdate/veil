#!/usr/bin/env bash
# Publishes the formula for a release tag to the Homebrew tap.
# Needs: TAG (e.g. v0.2.0) and HOMEBREW_TAP_TOKEN (fine-grained token with
# write access to moomdate/homebrew-tap only).
set -euo pipefail
: "${TAG:?}" "${HOMEBREW_TAP_TOKEN:?}"
repo=moomdate/veil
tap=moomdate/homebrew-tap
version=${TAG#v}
url="https://github.com/${repo}/archive/refs/tags/${TAG}.tar.gz"
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL "$url" -o "$work/src.tar.gz"
sha=$(shasum -a 256 "$work/src.tar.gz" | cut -d' ' -f1)

git clone --depth 1 "https://x-access-token:${HOMEBREW_TAP_TOKEN}@github.com/${tap}.git" "$work/tap"
mkdir -p "$work/tap/Formula"
"$here/render.sh" "$version" "$url" "$sha" > "$work/tap/Formula/veil.rb"

cd "$work/tap"
git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git add Formula/veil.rb
if git diff --cached --quiet; then
  echo "Formula already up to date"
  exit 0
fi
git commit -m "veil ${version}"
git push origin HEAD
echo "Published veil ${version} to ${tap}"
