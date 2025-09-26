#!/usr/bin/env bash
# Build script for DNSRecon-rs

set -e  # Exit on any error

echo "DNSRecon-rs Build Script"
echo "========================"

# Default values
RELEASE_MODE="release"
OUTPUT_DIR="dist"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --debug)
            RELEASE_MODE="debug"
            shift
            ;;
        --output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--debug] [--output-dir DIRECTORY]"
            echo "  --debug          Build in debug mode (default: release)"
            echo "  --output-dir     Output directory (default: dist)"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "Building in $RELEASE_MODE mode"
echo "Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/data"

# Build the project
if [ "$RELEASE_MODE" = "release" ]; then
    echo "Building release version..."
    cargo build --release
    BINARY_PATH="target/release/dnsrecon-rs"
else
    echo "Building debug version..."
    cargo build
    BINARY_PATH="target/debug/dnsrecon-rs"
fi

# Copy binary
echo "Copying binary to $OUTPUT_DIR/"
cp "$BINARY_PATH" "$OUTPUT_DIR/"

# Copy data files
echo "Copying data files to $OUTPUT_DIR/data/"
cp data/*.txt "$OUTPUT_DIR/data/"

# Create a README with usage instructions
cat > "$OUTPUT_DIR/README.md" << 'EOF'
# DNSRecon-rs

A high-performance DNS enumeration tool written in Rust.

## Usage

Run the tool with:
```bash
./dnsrecon-rs --help
```

### Examples:

Standard enumeration:
```bash
./dnsrecon-rs -d example.com -t std
```

Brute force enumeration (uses default wordlist):
```bash
./dnsrecon-rs -d example.com -t brt
```

Brute force with custom wordlist:
```bash
./dnsrecon-rs -d example.com -t brt -D data/subdomains-top1mil.txt
```

## Wordlists

This package includes several wordlists for DNS enumeration:

- `namelist.txt` - 1,911 common names
- `subdomains-top1mil-5000.txt` - 5,000 most common subdomains (default)
- `subdomains-top1mil-20000.txt` - 20,000 most common subdomains
- `subdomains-top1mil.txt` - 114,606 most common subdomains
- `snoop.txt` - Domains for DNS cache snooping

The tool will automatically use `data/subdomains-top1mil-5000.txt` as the default wordlist for brute force enumeration if none is specified.
EOF

echo "Build completed successfully!"
echo "Package created in $OUTPUT_DIR/"
echo ""
echo "To run:"
echo "  cd $OUTPUT_DIR"
echo "  ./dnsrecon-rs --help"