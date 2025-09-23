# DNSRecon-rs

A high-performance DNS enumeration tool written in Rust, based on the original [DNSRecon](https://github.com/darkoperator/dnsrecon) Python tool.


>[!NOTE]
> This project is under active development.  
> For now, only very basic funtionality implemented. 

## Installation

### From Source

1. Install Rust using [rustup](https://rustup.rs/)
2. Clone this repository
3. Build the project:
   ```bash
   cd dnsrecon-rs
   cargo build --release
   ```
4. The binary will be available at `target/release/dnsrecon-rs`


## Usage

```bash
# Basic enumeration
dnsrecon-rs -d example.com

# Get help
dnsrecon-rs --help
```

## Building Release Packages

The project includes build scripts to create self-contained packages:

### Windows
```powershell
# PowerShell
.\build.ps1
```

### Unix-like Systems
```bash
./build.sh
```

These scripts will:
1. Compile the Rust binary
2. Copy the binary to the output directory
3. Copy all wordlist files to a `data/` subdirectory
4. Generate documentation and usage instructions

## License

This project is licensed under the GNU General Public License v2.0.

## Acknowledgments

This project is a Rust reimplementation of the original [DNSRecon](https://github.com/darkoperator/dnsrecon) tool created by Carlos Perez.
