# PowerShell build script for DNSRecon-rs

param(
    [switch]$Debug,
    [string]$OutputDir = "dist"
)

Write-Host "DNSRecon-rs Build Script" -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green

# Set build mode
$ReleaseMode = if ($Debug) { "debug" } else { "release" }

Write-Host "Building in $ReleaseMode mode" -ForegroundColor Yellow
Write-Host "Output directory: $OutputDir" -ForegroundColor Yellow

# Create output directory
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
New-Item -ItemType Directory -Path "$OutputDir\data" -Force | Out-Null

# Build the project
if ($ReleaseMode -eq "release") {
    Write-Host "Building release version..." -ForegroundColor Cyan
    cargo build --release
    $BinaryPath = "target\release\dnsrecon-rs.exe"
} else {
    Write-Host "Building debug version..." -ForegroundColor Cyan
    cargo build
    $BinaryPath = "target\debug\dnsrecon-rs.exe"
}

# Copy binary
Write-Host "Copying binary to $OutputDir\" -ForegroundColor Cyan
Copy-Item $BinaryPath "$OutputDir\"

# Copy data files
Write-Host "Copying data files to $OutputDir\data\" -ForegroundColor Cyan
Copy-Item "data\*.txt" "$OutputDir\data\"

# Create a README with usage instructions
$ReadmeContent = @'
# DNSRecon-rs

A high-performance DNS enumeration tool written in Rust.

## Usage

Run the tool with:
```powershell
.\dnsrecon-rs.exe --help
```

### Examples:

Standard enumeration:
```powershell
.\dnsrecon-rs.exe -d example.com -t std
```

Brute force enumeration (uses default wordlist):
```powershell
.\dnsrecon-rs.exe -d example.com -t brt
```

Brute force with custom wordlist:
```powershell
.\dnsrecon-rs.exe -d example.com -t brt -D data/subdomains-top1mil.txt
```

## Wordlists

This package includes several wordlists for DNS enumeration:

- `namelist.txt` - 1,911 common names
- `subdomains-top1mil-5000.txt` - 5,000 most common subdomains (default)
- `subdomains-top1mil-20000.txt` - 20,000 most common subdomains
- `subdomains-top1mil.txt` - 114,606 most common subdomains
- `snoop.txt` - Domains for DNS cache snooping

The tool will automatically use `data/subdomains-top1mil-5000.txt` as the default wordlist for brute force enumeration if none is specified.
'@

Set-Content -Path "$OutputDir\README.md" -Value $ReadmeContent

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host "Package created in $OutputDir\" -ForegroundColor Green
Write-Host ""
Write-Host "To run:" -ForegroundColor Yellow
Write-Host "  cd $OutputDir" -ForegroundColor Yellow
Write-Host "  .\dnsrecon-rs.exe --help" -ForegroundColor Yellow