# 🦅 ScanHawk — Cyber Security Port Scanner

A fast, multi-threaded TCP port scanner for authorized network reconnaissance and cyber security auditing — built in pure Python with **zero third-party dependencies**.

> ⚠️ **Legal notice:** Only use ScanHawk against hosts and networks you own or have explicit written permission to test. Unauthorized scanning may be illegal under laws such as the U.S. Computer Fraud and Abuse Act or equivalent laws in your country. See [LICENSE](LICENSE) for the full disclaimer.

---

## Features

- 🚀 Multi-threaded TCP connect scanning (fast even on large port ranges)
- 🔎 Automatic service name guessing (`http`, `ssh`, `ftp`, etc.)
- 📡 Optional banner grabbing on open ports
- ⚡ `--top-ports` shortcut for a curated list of commonly used ports
- 📄 Export results to JSON or CSV
- 🖥️ Simple, readable CLI output with progress reporting
- 📦 No external dependencies — just Python 3.7+

---

## Installation

### 1. Prerequisites
- Python **3.7 or higher**
- pip (usually bundled with Python)

Check your Python version:
```bash
python3 --version
```

### 2. Clone or download the project
```bash
git clone https://github.com/yourusername/scanhawk.git
cd scanhawk
```
(Or simply download `scanhawk.py`, `requirements.txt`, `README.md`, and `LICENSE` into a folder.)

### 3. (Recommended) Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate
```

### 4. Install dependencies
ScanHawk uses only the Python standard library, so this step installs nothing extra — but it's included for convention and future-proofing:
```bash
pip install -r requirements.txt
```

### 5. Make the script executable (optional, macOS/Linux)
```bash
chmod +x scanhawk.py
```

---

## Usage

Basic syntax:
```bash
python3 scanhawk.py <target> [options] --i-have-permission
```

> The `--i-have-permission` flag is **required** every run — it's a built-in guardrail confirming you're authorized to scan the target.

### Examples

Scan the default range (ports 1–1024) on a target:
```bash
python3 scanhawk.py 192.168.1.10 --i-have-permission
```

Scan a specific range:
```bash
python3 scanhawk.py 192.168.1.10 -p 1-1000 --i-have-permission
```

Scan specific ports:
```bash
python3 scanhawk.py 192.168.1.10 -p 22,80,443 --i-have-permission
```

Scan common ports with banner grabbing:
```bash
python3 scanhawk.py scanme.nmap.org --top-ports --banner --i-have-permission
```

Export results to JSON and CSV:
```bash
python3 scanhawk.py 10.0.0.5 --top-ports --json results.json --csv results.csv --i-have-permission
```

Verbose mode (shows scan progress):
```bash
python3 scanhawk.py 192.168.1.10 -p 1-5000 -v --i-have-permission
```

### All options
| Flag | Description | Default |
|---|---|---|
| `target` | Target IP address or hostname | *required* |
| `-p`, `--ports` | Ports to scan, e.g. `22,80,443` or `1-1000` | `1-1024` |
| `--top-ports` | Scan a curated list of commonly used ports instead of `-p` | off |
| `-t`, `--threads` | Number of concurrent worker threads | `200` |
| `--timeout` | Per-connection timeout in seconds | `0.75` |
| `--banner` | Attempt to grab a service banner on open ports | off |
| `--json FILE` | Write results to a JSON file | — |
| `--csv FILE` | Write results to a CSV file | — |
| `-v`, `--verbose` | Show progress while scanning | off |
| `--i-have-permission` | Confirm you're authorized to scan this target | *required* |

---

## Testing it safely

`scanme.nmap.org` is a host the Nmap project maintains specifically for people to legally test scanners against:
```bash
python3 scanhawk.py scanme.nmap.org --top-ports --banner --i-have-permission
```

You can also test locally against `127.0.0.1` or your own LAN devices.

---

## Roadmap ideas

- UDP scanning support
- OS fingerprinting hints
- Colorized terminal output
- Simple HTML/web report output

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

ScanHawk is provided for educational and authorized cyber security testing purposes only. The authors accept no liability for misuse. Always obtain permission before scanning any system you do not own.
