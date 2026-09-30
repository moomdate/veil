#!/usr/bin/env bash
# Renders veil.rb from the template.
#   render.sh VERSION URL SHA256 > veil.rb
set -euo pipefail
version=${1:?version}; url=${2:?url}; sha=${3:?sha256}
here=$(cd "$(dirname "$0")" && pwd)
sed -e "s|@VERSION@|${version}|g" -e "s|@URL@|${url}|g" -e "s|@SHA256@|${sha}|g" "$here/veil.rb.tmpl"
