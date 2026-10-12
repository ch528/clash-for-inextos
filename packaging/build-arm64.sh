#!/bin/bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="${VERSION:-}"
PACKAGE_VERSION="${PACKAGE_VERSION:-${VERSION:-1.0.0}}"
if [[ -z "$VERSION" ]]; then
  if [[ "$PACKAGE_VERSION" =~ ^1\.0\.0-([0-9]+)$ ]]; then
    VERSION="1.0.${BASH_REMATCH[1]}"
  else
    VERSION="$PACKAGE_VERSION"
  fi
fi
TARGET_ARCH="${TARGET_ARCH:-$(dpkg --print-architecture)}"
GO_BIN="${GO_BIN:-go}"
OUT_DIR="${OUT_DIR:-$ROOT/build}"
UPSTREAM_REVISION="42c26d8ad44373980ef3e6c4113de3beedb3d876"
ZASHBOARD_VERSION="v3.29.1"
MIHOMO_VERSION="v1.19.32"
MIHOMO_URL="https://github.com/MetaCubeX/mihomo/releases/download/$MIHOMO_VERSION/mihomo-linux-arm64-$MIHOMO_VERSION.gz"
MIHOMO_GZ_SHA256="9dd862e28b46ff7d775f169cceebc28deccaa0a9e804237d421cd2571e0caba0"
MIHOMO_SHA256="c80df2ca5159567804da883401e0118908fc1155e05df2baf3dbd4d3ecfc3754"
ZASHBOARD_SHA256="4f16cce229e223bd07b5a3daccfbfb8bf349d7335572d412959284ab6c9bab50"
ZASHBOARD_ZIP="$ROOT/vendor/zashboard/v3.29.1-dist.zip"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%d)}"

if [[ "$TARGET_ARCH" != "arm64" ]]; then
  echo "Build this package for arm64." >&2
  exit 1
fi
if [[ ! -s "$ROOT/web/dist/index.html" ]]; then
  echo "Build web/dist before packaging." >&2
  exit 1
fi

STAGE="$(mktemp -d)"
ZASHBOARD_STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" "$ZASHBOARD_STAGE"' EXIT
mkdir -p "$STAGE/DEBIAN" "$STAGE/opt/inextos-clash/bin" "$STAGE/opt/inextos-clash/web" "$STAGE/opt/inextos-clash/dashboard" "$STAGE/opt/inextos-clash/upstream" \
  "$STAGE/etc/inextos-clash/mihomo" "$STAGE/usr/lib/systemd/system" "$STAGE/usr/bin" "$STAGE/usr/share/doc/inextos-clash" \
  "$STAGE/usr/share/icons/hicolor/64x64/apps" "$STAGE/usr/share/icons/hicolor/128x128/apps" "$STAGE/usr/share/icons/hicolor/256x256/apps"

GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$GO_BIN" -C "$ROOT/backend" build -trimpath -ldflags "-s -w -X main.appVersion=$VERSION -X main.upstreamRevision=$UPSTREAM_REVISION -X main.dashboardVersion=$ZASHBOARD_VERSION -X main.buildDate=$BUILD_DATE" -o "$STAGE/opt/inextos-clash/bin/inextos-clash-server" .
if [[ -n "${MIHOMO_BIN:-}" ]]; then
  cp "$MIHOMO_BIN" "$STAGE/opt/inextos-clash/bin/mihomo"
  echo "$MIHOMO_SHA256  $STAGE/opt/inextos-clash/bin/mihomo" | sha256sum -c -
else
  curl -fsSL --retry 3 -o "$STAGE/mihomo.gz" "$MIHOMO_URL"
  echo "$MIHOMO_GZ_SHA256  $STAGE/mihomo.gz" | sha256sum -c -
  gzip -dc "$STAGE/mihomo.gz" > "$STAGE/opt/inextos-clash/bin/mihomo"
  rm "$STAGE/mihomo.gz"
fi
chmod 0755 "$STAGE/opt/inextos-clash/bin/inextos-clash-server" "$STAGE/opt/inextos-clash/bin/mihomo"
if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "aarch64" ]]; then
  "$STAGE/opt/inextos-clash/bin/mihomo" -v | grep -q "$MIHOMO_VERSION"
fi

echo "$ZASHBOARD_SHA256  $ZASHBOARD_ZIP" | sha256sum -c -
unzip -q "$ZASHBOARD_ZIP" -d "$ZASHBOARD_STAGE"
test -s "$ZASHBOARD_STAGE/dist/index.html"
test -s "$ZASHBOARD_STAGE/dist/THIRD_PARTY_NOTICES.md"
cp -a "$ZASHBOARD_STAGE/dist/." "$STAGE/opt/inextos-clash/dashboard/"

cp "$ROOT/web/dist/index.html" "$STAGE/opt/inextos-clash/web/index.html"
cp "$ROOT/web/dist"/*.png "$STAGE/opt/inextos-clash/web/"
mkdir -p "$STAGE/opt/inextos-clash/web/assets"
while IFS= read -r asset; do
  cp "$ROOT/web/dist/${asset#/}" "$STAGE/opt/inextos-clash/web/$asset"
done < <(grep -oE '/assets/[^" ]+' "$ROOT/web/dist/index.html")
cp "$ROOT/packaging/app.yaml" "$STAGE/etc/inextos-clash/app.yaml"
for unit in inextos-clash.service inextos-clash-helper.service inextos-clash-mihomo.service inextos-clash-app-update.service inextos-clash-network-rollback.service inextos-clash-network-rollback.timer; do
  cp "$ROOT/packaging/$unit" "$STAGE/usr/lib/systemd/system/$unit"
done
cp "$ROOT/docs/inextos-shortcut.md" "$STAGE/usr/share/doc/inextos-clash/inextos-shortcut.md"
cp "$ROOT/docs/tun-helper-design.md" "$STAGE/usr/share/doc/inextos-clash/tun-helper-design.md"
for doc in README.md INSTALL.md UPGRADE.md NETWORK.md TUN.md RECOVERY.md SECURITY.md THIRD_PARTY_LICENSES.md; do
  cp "$ROOT/docs/$doc" "$STAGE/usr/share/doc/inextos-clash/$doc"
done
cp "$ROOT/upstream/README.md" "$STAGE/opt/inextos-clash/upstream/README.md"
cp "$ROOT/upstream/LICENSE" "$STAGE/opt/inextos-clash/upstream/LICENSE"
cp "$ROOT/vendor/zashboard/LICENSE" "$STAGE/usr/share/doc/inextos-clash/ZASHBOARD_LICENSE"
cp "$ZASHBOARD_STAGE/dist/THIRD_PARTY_NOTICES.md" "$STAGE/usr/share/doc/inextos-clash/ZASHBOARD_THIRD_PARTY_NOTICES.md"
mkdir -p "$STAGE/opt/inextos-clash/web/licenses"
cp "$ROOT/docs/THIRD_PARTY_LICENSES.md" "$STAGE/opt/inextos-clash/web/licenses/THIRD_PARTY_LICENSES.md"
ln -s /opt/inextos-clash/bin/inextos-clash-server "$STAGE/usr/bin/inextos-clash"
for size in 64 128 256; do
  cp "$ROOT/icons/inextos-clash-$size.png" "$STAGE/usr/share/icons/hicolor/${size}x${size}/apps/inextos-clash.png"
done

sed "s/^Version:.*/Version: $PACKAGE_VERSION/" "$ROOT/packaging/control" > "$STAGE/DEBIAN/control"
cp "$ROOT/packaging/conffiles" "$STAGE/DEBIAN/conffiles"
cp "$ROOT/packaging/postinst" "$STAGE/DEBIAN/postinst"
cp "$ROOT/packaging/prerm" "$STAGE/DEBIAN/prerm"
cp "$ROOT/packaging/postrm" "$STAGE/DEBIAN/postrm"
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"
chmod 0755 "$STAGE"
mkdir -p "$OUT_DIR"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT_DIR/inextos-clash_${PACKAGE_VERSION}_arm64.deb"
