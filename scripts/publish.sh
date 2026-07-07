#!/usr/bin/env bash
# ============================================================
# publish.sh — Build y publica apileaks en PyPI
#
# Uso:
#   ./scripts/publish.sh           → publica en PyPI real
#   ./scripts/publish.sh --test    → publica en TestPyPI primero
# ============================================================
set -euo pipefail

PUBLISH_TARGET="pypi"
if [[ "${1:-}" == "--test" ]]; then
    PUBLISH_TARGET="testpypi"
fi

echo "==> Limpiando builds anteriores..."
rm -rf dist/ build/ *.egg-info

echo "==> Instalando build tools..."
python -m pip install --upgrade build twine

echo "==> Construyendo sdist + wheel..."
python -m build

echo "==> Contenido del paquete:"
ls -lh dist/

echo "==> Verificando el paquete..."
python -m twine check dist/*

if [[ "$PUBLISH_TARGET" == "testpypi" ]]; then
    echo "==> Subiendo a TestPyPI (https://test.pypi.org)..."
    python -m twine upload --repository testpypi dist/*
    echo ""
    echo "Prueba la instalación con:"
    echo "  pip install --index-url https://test.pypi.org/simple/ apileaks"
    echo "  uv tool install --index https://test.pypi.org/simple/ apileaks"
else
    echo "==> Subiendo a PyPI..."
    python -m twine upload dist/*
    echo ""
    echo "Instalación disponible con:"
    echo "  pip install apileaks"
    echo "  uv tool install apileaks"
    echo "  pipx install apileaks"
fi
