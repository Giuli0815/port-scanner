#!/usr/bin/env bash
# Build PortScanner.dmg for macOS
# Run this script on a Mac inside the pythonpj folder:
#   chmod +x build_mac.sh && ./build_mac.sh
#
# Requirements:
#   pip3 install pyinstaller customtkinter

set -euo pipefail

APP_NAME="Port Scanner"
BUNDLE="PortScanner.app"
DMG="PortScanner.dmg"
VOL_NAME="Port Scanner"

echo "==> Cleaning previous build..."
rm -rf build "dist/${BUNDLE}" "dist/${DMG}" dist/dmg_stage

echo "==> Building .app bundle with PyInstaller..."
pyinstaller PortScanner_mac.spec

echo "==> Staging DMG contents..."
mkdir -p dist/dmg_stage
cp -r "dist/${BUNDLE}" dist/dmg_stage/
ln -s /Applications dist/dmg_stage/Applications

echo "==> Creating DMG with hdiutil..."
hdiutil create \
    -volname "${VOL_NAME}" \
    -srcfolder dist/dmg_stage \
    -ov \
    -format UDZO \
    "dist/${DMG}"

echo "==> Cleaning up staging area..."
rm -rf dist/dmg_stage

echo ""
echo "Done!  dist/${DMG} is ready."
echo "Copy it to pythonpj/dist/ on your Windows machine and the download link will work."
