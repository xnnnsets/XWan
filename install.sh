#!/bin/bash
wget https://github.com/XTLS/Xray-core/releases/download/v25.10.15/Xray-android-arm64-v8a.zip
unzip Xray-android-arm64-v8a.zip
cp xray $PREFIX/bin/
chmod +x $PREFIX/bin/xray
rm Xray-android-arm64-v8a.zip geoip.dat geosite.dat
echo "[!] SUKSES INSTALL XRAY"