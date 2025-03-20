# LNK File Analyzer

A cybersecurity forensics tool for Windows shortcut (.LNK) file analysis, focusing on detection of command injection and evasion techniques.

## Overview

LNK File Analyzer is a specialized tool designed to help security professionals identify potentially malicious Windows shortcuts. It detects various techniques used to obfuscate malicious commands in .LNK files, including:

- Whitespace padding
- Command injection characters
- Path traversal sequences
- PowerShell execution patterns
- Special character encoding
- Environment variable manipulation

## Background

This tool was developed in response to Windows .LNK file vulnerabilities similar to those described in:
[Windows Zero-Day Flaw](https://thehackernews.com/2025/03/unpatched-windows-zero-day-flaw.html)

## Features

- Detailed forensic analysis of .LNK files
- Recursive directory scanning
- Custom file pattern matching
- Supports both individual file and bulk analysis
- Extensive error handling and reporting
- Comprehensive logging for forensic documentation

## Installation

### Prerequisites

- Windows operating system
- .NET 9.0 or later

### Setup

1. Clone this repository:
   >>>
   git clone https://github.com/yourusername/LnkFileAnalyzer.git
   >>>

2. Build the project:
   >>>
   cd LnkFileAnalyzer
   dotnet build
   >>>

3. Run the application:
   >>>
   cd bin/Debug/net9.0-windows
   LnkFileAnalyzer.exe
   >>>

## Usage

### Basic Usage

>>>
LnkFileAnalyzer.exe [options]
>>>

### Command Line Options

| Option | Description |
|--------|-------------|
| `--path`, `-p` | Directory to scan (default: current directory) |
| `--recurse`, `-r` | Scan subdirectories recursively |
| `--filespec`, `-f` | File specification (default: *.lnk) |
| `--verbose`, `-v` | Enable verbose output |
| `--logfile`, `-l` | Custom log file path |
| `--continue`, `-c` | Continue on errors (default: true) |
| `--help`, `-h` | Show help message |

### Examples

Scan current directory:
>>>
LnkFileAnalyzer.exe
>>>

Scan specific directory recursively:
>>>
LnkFileAnalyzer.exe --path C:\Users --recurse
>>>

Analyze a specific file:
>>>
LnkFileAnalyzer.exe --path C:\Suspicious\test.lnk
>>>

Scan for specific pattern with verbose output:
>>>
LnkFileAnalyzer.exe -p C:\Users\Desktop -f suspicious*.lnk -v
>>>

## Detection Patterns

The analyzer looks for several suspicious indicators, including:

1. **Command Injection Characters**: `&`, `|`, `;`, `$`, `(`, `)`, etc.
2. **Suspicious Whitespace**: Tabs, line feeds, vertical tabs, form feeds, etc.
3. **Path Traversal**: Sequences like `..` that might access unexpected directories
4. **PowerShell Patterns**: Arguments like `-EncodedCommand`, `-WindowStyle Hidden`, etc.
5. **Special Character Usage**: Non-printable characters, Unicode padding, etc.

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success - No suspicious files found |
| 1 | Errors occurred during analysis |
| 2 | Suspicious files found |
| -1 | Critical error |

## Testing

A PowerShell script is included to generate test .LNK files with various suspicious patterns:

>>>
powershell -File CreateTestLNKFiles.ps1
>>>

This creates sample files in the `LNK_Test_Files` directory.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- Your Name/Organization
- Generated with assistance from Claude AI (Anthropic)

## Disclaimer

This tool is intended for cybersecurity professionals and researchers. Use responsibly and only analyze files you have permission to examine. Always follow applicable laws and regulations related to cybersecurity activities.# LnkFileAnalyzer