# Homebrew Formula para apileaks
# Para usar un tap propio:
#   brew tap tu-usuario/apileaks https://github.com/tu-usuario/homebrew-apileaks
#   brew install apileaks
#
# O instalar directamente desde el archivo local:
#   brew install --formula scripts/apileaks.rb

class Apileaks < Formula
  include Language::Python::Virtualenv

  desc "Enterprise-grade API fuzzing and OWASP testing tool"
  homepage "https://github.com/apileak/owasp-enhancement"
  # Actualizar url y sha256 después de publicar en PyPI o GitHub Releases
  url "https://files.pythonhosted.org/packages/source/a/apileaks/apileaks-0.2.0.tar.gz"
  sha256 "REEMPLAZAR_CON_SHA256_REAL_DEL_TARBALL"
  license "MIT"

  bottle do
    root_url "https://github.com/tu-usuario/homebrew-apileaks/releases/download/apileaks-0.2.0"
    sha256 cellar: :any_skip_relocation, arm64_sonoma: "HASH_ARM64"
    sha256 cellar: :any_skip_relocation, x86_64_linux: "HASH_LINUX"
  end

  depends_on "python@3.12"

  # Dependencias Python (listar todas para que brew las instale en el virtualenv)
  resource "click" do
    url "https://files.pythonhosted.org/packages/source/c/click/click-8.1.7.tar.gz"
    sha256 "ca9853ad459e787e2192211578cc907e7594e294c7ccc834310722b41b9ca6de"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-13.7.0.tar.gz"
    sha256 "5cb5123b5cf9ee70584244246816e9114227e0b98ad9176eede6ad54bf5403fa"
  end

  # ... agregar el resto de dependencias con sus sha256 reales

  def install
    virtualenv_install_with_resources
  end

  test do
    system bin/"apileaks", "--version"
  end
end
