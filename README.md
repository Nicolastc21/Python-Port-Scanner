# Python Multithreaded Port Scanner 🔍

A fast, multithreaded TCP port scanner written in Python. This tool not only detects open ports but also performs **Service Detection** and **Banner Grabbing** to identify the software running on the target ports.

Created by **Nicolas-Costin Tanasache**.

## 🚀 Features
- **Multithreaded Scanning:** Uses Python's `threading` and `Queue` for fast concurrent scanning.
- **Service Detection:** Maps open ports to known services (e.g., 22 -> SSH, 80 -> HTTP).
- **Banner Grabbing:** Proactively sends payloads to grab service banners (versions/software details).
- **Thread-Safe Console Output:** Clean, real-time results without text overlap.
- **Customizable:** Easily change the target, port range, thread count, and timeout limits.

## 🛠️ Requirements
- Python 3.x
- No external libraries required (uses only Python standard library: `socket`, `threading`, `argparse`).

## 💻 Usage

Run the script from the terminal/command prompt:

```bash
python python_port_scanner.py <host> [start_port] [end_port] [--threads N] [--timeout T]
