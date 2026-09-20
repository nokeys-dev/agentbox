#!/bin/sh
# Builds agentbox_<version>_amd64.deb from the packed npm tarball and the Linux single-file
# executable: the package tree under /usr/lib/agentbox and the executable at /usr/bin/agentbox.
# Usage: sh scripts/release/deb.sh <version> <npm tarball> <linux binary> <out dir>
set -eu
version=$1; tarball=$2; binary=$3; out=${4:-dist}
stage=$(mktemp -d)
mkdir -p "$stage/DEBIAN" "$stage/usr/lib/agentbox" "$stage/usr/bin"
tar -xzf "$tarball" -C "$stage/usr/lib/agentbox" --strip-components=1
install -m 755 "$binary" "$stage/usr/bin/agentbox"
node scripts/release/manifests.js "$version" "$(printf '%064d' 0)" "$(printf '%064d' 0)" "$stage/tmp-manifests" >/dev/null
cp "$stage/tmp-manifests/control" "$stage/DEBIAN/control"; rm -rf "$stage/tmp-manifests"
find "$stage/usr" -type d -exec chmod 755 {} +
mkdir -p "$out"
dpkg-deb --build --root-owner-group "$stage" "$out/agentbox_${version}_amd64.deb"
rm -rf "$stage"
echo "built $out/agentbox_${version}_amd64.deb"
