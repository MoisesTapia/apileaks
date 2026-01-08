# APILeak Docker Build Script (PowerShell)
# Builds multi-architecture Docker images for APILeak OWASP Enhancement

param(
    [string]$Version = "0.1.0",
    [string]$Registry = $env:DOCKER_REGISTRY,
    [string]$Platforms = "linux/amd64,linux/arm64",
    [switch]$Push = $false,
    [switch]$NoCache = $false,
    [switch]$Load = $false,
    [switch]$Help = $false
)

# Configuration
$ImageName = "apileak"
$BuilderName = "apileak-builder"

# Colors for output
$Colors = @{
    Red = "Red"
    Green = "Green"
    Yellow = "Yellow"
    Blue = "Blue"
    White = "White"
}

# Logging functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor $Colors.Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor $Colors.Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor $Colors.Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor $Colors.Red
}

# Help function
function Show-Help {
    @"
APILeak Docker Build Script (PowerShell)

Usage: .\build-docker.ps1 [OPTIONS]

Options:
    -Version VERSION        Set image version (default: $Version)
    -Registry REGISTRY      Set Docker registry (default: none)
    -Push                   Push images to registry
    -Platforms PLATFORMS    Target platforms (default: $Platforms)
    -NoCache                Build without cache
    -Load                   Load image to local Docker (single platform only)
    -Help                   Show this help message

Examples:
    # Build for local development
    .\build-docker.ps1 -Load

    # Build and push to registry
    .\build-docker.ps1 -Registry "ghcr.io/myorg" -Push

    # Build specific version
    .\build-docker.ps1 -Version "1.0.0" -Push

Environment Variables:
    DOCKER_REGISTRY         Default registry to use
"@
}

# Show help if requested
if ($Help) {
    Show-Help
    exit 0
}

# Override push from environment if set
if ($env:PUSH -eq "true") {
    $Push = $true
}

# Construct full image name
if ($Registry) {
    $FullImageName = "$Registry/$ImageName"
} else {
    $FullImageName = $ImageName
}

# If Load is specified, use single platform
if ($Load) {
    $Platforms = "linux/amd64"
}

# Validate Docker and buildx
Write-Info "Checking Docker and buildx availability..."

try {
    $null = docker --version
} catch {
    Write-Error "Docker is not installed or not in PATH"
    exit 1
}

try {
    $null = docker buildx version
} catch {
    Write-Error "Docker buildx is not available"
    Write-Info "Please install Docker buildx or use a newer version of Docker"
    exit 1
}

# Create buildx builder if it doesn't exist
try {
    $null = docker buildx inspect $BuilderName 2>$null
    Write-Info "Using existing buildx builder: $BuilderName"
    docker buildx use $BuilderName
} catch {
    Write-Info "Creating buildx builder: $BuilderName"
    docker buildx create --name $BuilderName --use
}

# Prepare build arguments
$BuildArgs = @(
    "--platform", $Platforms,
    "--tag", "$FullImageName`:$Version",
    "--tag", "$FullImageName`:latest",
    "--file", "Dockerfile",
    "."
)

# Add optional arguments
if ($NoCache) {
    $BuildArgs += "--no-cache"
}

if ($Load) {
    $BuildArgs += "--load"
} elseif ($Push) {
    $BuildArgs += "--push"
}

# Display build information
Write-Info "Build Configuration:"
Write-Host "  Image Name: $FullImageName" -ForegroundColor $Colors.White
Write-Host "  Version: $Version" -ForegroundColor $Colors.White
Write-Host "  Platforms: $Platforms" -ForegroundColor $Colors.White
Write-Host "  Registry: $(if ($Registry) { $Registry } else { '(local)' })" -ForegroundColor $Colors.White
Write-Host "  Push: $Push" -ForegroundColor $Colors.White
Write-Host "  Load: $Load" -ForegroundColor $Colors.White

# Check if Dockerfile exists
if (-not (Test-Path "Dockerfile")) {
    Write-Error "Dockerfile not found in current directory"
    exit 1
}

# Build the image
Write-Info "Starting Docker build..."
Write-Host "Command: docker buildx build $($BuildArgs -join ' ')" -ForegroundColor $Colors.White

try {
    & docker buildx build @BuildArgs
    Write-Success "Docker build completed successfully"
} catch {
    Write-Error "Docker build failed"
    exit 1
}

# Display image information
if ($Load) {
    Write-Info "Image loaded to local Docker:"
    docker images $FullImageName | Select-Object -First 2
    
    # Test the image
    Write-Info "Testing the built image..."
    try {
        $null = docker run --rm "$FullImageName`:$Version" --help 2>$null
        Write-Success "Image test passed"
    } catch {
        Write-Warning "Image test failed - image may not be working correctly"
    }
}

if ($Push) {
    Write-Success "Images pushed to registry: $Registry"
    Write-Info "Available tags:"
    Write-Host "  - $FullImageName`:$Version" -ForegroundColor $Colors.White
    Write-Host "  - $FullImageName`:latest" -ForegroundColor $Colors.White
}

Write-Success "Build process completed!"

# Usage examples
if ($Load) {
    Write-Host ""
    Write-Info "Usage examples:"
    Write-Host "  # Run directory scan" -ForegroundColor $Colors.White
    Write-Host "  docker run --rm $FullImageName`:$Version dir --target https://api.example.com" -ForegroundColor $Colors.White
    Write-Host ""
    Write-Host "  # Run with custom configuration" -ForegroundColor $Colors.White
    Write-Host "  docker run --rm -v `$(pwd)/config:/app/config $FullImageName`:$Version full --config config/api-config.yaml" -ForegroundColor $Colors.White
}