# APILeak OWASP Enhancement Makefile
# Gestión de entorno virtual y desarrollo

.PHONY: help venv install install-dev test clean lint format run

# Variables
PYTHON = python3.11
VENV_DIR = venv
VENV_PYTHON = $(VENV_DIR)/bin/python
VENV_PIP = $(VENV_DIR)/bin/pip
VENV_ACTIVATE = $(VENV_DIR)/bin/activate

# Detectar sistema operativo
ifeq ($(OS),Windows_NT)
    VENV_PYTHON = $(VENV_DIR)/Scripts/python.exe
    VENV_PIP = $(VENV_DIR)/Scripts/pip.exe
    VENV_ACTIVATE = $(VENV_DIR)/Scripts/activate
endif

help: ## Mostrar ayuda
	@echo "APILeak OWASP Enhancement - Comandos disponibles:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

venv: ## Crear entorno virtual
	@echo "Creando entorno virtual..."
	$(PYTHON) -m venv $(VENV_DIR)
	@echo "Entorno virtual creado en $(VENV_DIR)"
	@echo "Para activar: source $(VENV_ACTIVATE)"

install: venv ## Instalar dependencias en entorno virtual
	@echo "Instalando dependencias..."
	$(VENV_PIP) install --upgrade pip
	$(VENV_PIP) install -r requirements.txt
	@echo "Dependencias instaladas correctamente"

install-dev: install ## Instalar dependencias de desarrollo
	@echo "Instalando dependencias de desarrollo..."
	$(VENV_PIP) install pytest pytest-asyncio pytest-mock hypothesis black flake8 mypy
	@echo "Dependencias de desarrollo instaladas"

install-editable: install ## Instalar en modo desarrollo (editable)
	@echo "Instalando APILeak en modo desarrollo..."
	$(VENV_PIP) install -e .
	@echo "APILeak instalado en modo desarrollo"

test: ## Ejecutar tests
	@echo "Ejecutando tests..."
	$(VENV_PYTHON) -m pytest tests/ -v

test-coverage: ## Ejecutar tests con cobertura
	@echo "Ejecutando tests con cobertura..."
	$(VENV_PIP) install coverage
	$(VENV_PYTHON) -m coverage run -m pytest tests/
	$(VENV_PYTHON) -m coverage report
	$(VENV_PYTHON) -m coverage html

lint: ## Ejecutar linting
	@echo "Ejecutando linting..."
	$(VENV_PYTHON) -m flake8 core/ modules/ utils/ apileaks.py
	$(VENV_PYTHON) -m mypy core/ modules/ utils/ apileaks.py --ignore-missing-imports

format: ## Formatear código
	@echo "Formateando código..."
	$(VENV_PYTHON) -m black core/ modules/ utils/ apileaks.py

format-check: ## Verificar formato del código
	@echo "Verificando formato del código..."
	$(VENV_PYTHON) -m black --check core/ modules/ utils/ apileaks.py

run: ## Ejecutar APILeak con configuración de ejemplo
	@echo "Ejecutando APILeak..."
	$(VENV_PYTHON) apileaks.py --config config/sample_config.yaml --help

run-example: ## Ejecutar ejemplo completo (requiere target válido)
	@echo "Para ejecutar un escaneo real, edita config/sample_config.yaml con un target válido"
	@echo "Luego ejecuta: make venv && make install && source $(VENV_ACTIVATE) && python apileaks.py --config config/sample_config.yaml"

clean: ## Limpiar archivos temporales
	@echo "Limpiando archivos temporales..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/
	rm -rf dist/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/

clean-venv: clean ## Limpiar entorno virtual
	@echo "Eliminando entorno virtual..."
	rm -rf $(VENV_DIR)

reinstall: clean-venv install ## Reinstalar completamente

check-python: ## Verificar versión de Python
	@echo "Verificando Python..."
	@$(PYTHON) --version || (echo "Error: Python 3.11+ requerido" && exit 1)
	@echo "Python OK"

setup-dev: check-python venv install-dev install-editable ## Configuración completa de desarrollo
	@echo ""
	@echo "✅ Configuración de desarrollo completada"
	@echo ""
	@echo "Para activar el entorno virtual:"
	@echo "  source $(VENV_ACTIVATE)"
	@echo ""
	@echo "Para ejecutar APILeak:"
	@echo "  python apileaks.py --config config/sample_config.yaml --help"
	@echo ""
	@echo "Para ejecutar tests:"
	@echo "  make test"

# Comandos de Docker (opcional)
docker-build: ## Construir imagen Docker
	@echo "Construyendo imagen Docker..."
	docker build -t apileak:latest .

docker-run: ## Ejecutar en Docker
	@echo "Ejecutando APILeak en Docker..."
	docker run --rm \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/reports:/app/reports \
		-v $(PWD)/wordlists:/app/wordlists \
		apileak:latest --help

docker-run-dir: ## Ejecutar fuzzing de directorios en Docker
	@echo "Ejecutando fuzzing de directorios en Docker..."
	@echo "Uso: make docker-run-dir TARGET=https://api.example.com"
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: Especifica TARGET=https://api.example.com"; \
		exit 1; \
	fi
	docker run --rm \
		-v $(PWD)/reports:/app/reports \
		-v $(PWD)/wordlists:/app/wordlists \
		apileak:latest dir \
		--target $(TARGET) \
		--wordlist wordlists/endpoints.txt \
		--output docker-dir-scan

docker-run-full: ## Ejecutar escaneo completo en Docker
	@echo "Ejecutando escaneo completo en Docker..."
	@echo "Uso: make docker-run-full TARGET=https://api.example.com"
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: Especifica TARGET=https://api.example.com"; \
		exit 1; \
	fi
	docker run --rm \
		-v $(PWD)/config:/app/config \
		-v $(PWD)/reports:/app/reports \
		-v $(PWD)/wordlists:/app/wordlists \
		apileak:latest full \
		--target $(TARGET) \
		--output docker-full-scan

docker-compose-up: ## Ejecutar con docker-compose
	@echo "Ejecutando con docker-compose..."
	docker-compose up --build

docker-compose-scan: ## Ejecutar escaneo con docker-compose
	@echo "Ejecutando escaneo con docker-compose..."
	@echo "Uso: make docker-compose-scan TARGET=https://api.example.com"
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: Especifica TARGET=https://api.example.com"; \
		exit 1; \
	fi
	APILEAK_TARGET=$(TARGET) docker-compose run --rm apileak full