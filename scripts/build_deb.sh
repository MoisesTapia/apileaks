#!/usr/bin/env bash
# ============================================================
# build_deb.sh — Empaqueta apileaks como .deb para Kali/Parrot/Debian/Ubuntu
#
# Requiere: dpkg-deb, python3, pip3
# Ejecutar en Linux o en un contenedor Debian/Ubuntu
# ============================================================
set -euo pipefail

PKG_NAME="apileaks"
PKG_VERSION="0.2.0"
PKG_ARCH="all"          # Python puro = architecture independent
MAINTAINER="APILeak Team <team@apileak.com>"
DESCRIPTION="Enterprise-grade API fuzzing and OWASP testing tool"
DEB_DIR="deb_build/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}"

echo "==> Limpiando build anterior..."
rm -rf deb_build/
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/lib/python3/dist-packages"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/usr/share/doc/${PKG_NAME}"
mkdir -p "${DEB_DIR}/usr/share/${PKG_NAME}/wordlists"
mkdir -p "${DEB_DIR}/usr/share/${PKG_NAME}/config"

# ---- Instalar el paquete Python en el directorio staging ----
echo "==> Instalando paquete Python en staging..."
pip3 install \
    --target "${DEB_DIR}/usr/lib/python3/dist-packages" \
    --no-deps \
    .

# ---- Copiar wordlists y config (recursos de datos) ----
echo "==> Copiando recursos..."
cp -r wordlists/*.txt "${DEB_DIR}/usr/share/${PKG_NAME}/wordlists/" 2>/dev/null || true
cp -r config/ "${DEB_DIR}/usr/share/${PKG_NAME}/config/" 2>/dev/null || true

# ---- Wrapper script en /usr/bin ----
cat > "${DEB_DIR}/usr/bin/apileaks" << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/lib/python3/dist-packages")
from apileaks import cli
if __name__ == "__main__":
    cli()
EOF
chmod +x "${DEB_DIR}/usr/bin/apileaks"

# ---- Documentación ----
cp README.md "${DEB_DIR}/usr/share/doc/${PKG_NAME}/" 2>/dev/null || true
cp LICENSE   "${DEB_DIR}/usr/share/doc/${PKG_NAME}/" 2>/dev/null || true

# Comprimir changelog (requerido por lintian)
cat > /tmp/changelog << EOF
${PKG_NAME} (${PKG_VERSION}) unstable; urgency=medium

  * Initial Debian package release.

 -- ${MAINTAINER}  $(date -R)
EOF
gzip -9 -c /tmp/changelog > "${DEB_DIR}/usr/share/doc/${PKG_NAME}/changelog.Debian.gz"

# ---- DEBIAN/control ----
# Calculamos el tamaño instalado aproximado
INSTALLED_SIZE=$(du -sk "${DEB_DIR}" | cut -f1)

cat > "${DEB_DIR}/DEBIAN/control" << EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Section: net
Priority: optional
Architecture: ${PKG_ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: ${MAINTAINER}
Depends: python3 (>= 3.11), python3-pip
Homepage: https://github.com/apileak/owasp-enhancement
Description: ${DESCRIPTION}
 APILeaks is an enterprise-grade API security testing tool that covers
 OWASP API Top 10 vulnerabilities including BOLA, broken authentication,
 excessive data exposure, SSRF, injection, and more.
EOF

# ---- DEBIAN/postinst (instalar dependencias Python en postinst) ----
cat > "${DEB_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e
# Instalar dependencias Python del paquete
pip3 install --quiet \
    structlog pydantic PyYAML click \
    "httpx[socks]" aiohttp requests orjson \
    jinja2 lxml cryptography tqdm colorama rich \
    2>/dev/null || true
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

# ---- Build .deb ----
echo "==> Construyendo .deb..."
dpkg-deb --build "${DEB_DIR}"

DEB_FILE="deb_build/${PKG_NAME}_${PKG_VERSION}_${PKG_ARCH}.deb"
echo ""
echo "✅ Paquete creado: ${DEB_FILE}"
echo ""
echo "Para instalar:"
echo "  sudo dpkg -i ${DEB_FILE}"
echo "  sudo apt-get install -f   # instala dependencias faltantes"
echo ""
echo "Para verificar (lintian):"
echo "  lintian ${DEB_FILE}"
