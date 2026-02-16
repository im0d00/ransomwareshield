# RansomwareShield

A Python-based ransomware detection and prevention tool that monitors file system activity for suspicious behavior patterns commonly associated with ransomware attacks.

## Features

- **Real-time file system monitoring** — Watches directories for suspicious file operations such as mass file renaming, rapid encryption-like modifications, and deletion patterns.
- **Entropy analysis** — Detects high-entropy file content changes that may indicate encryption activity.
- **Configurable monitoring rules** — Customize watched directories, file extensions, and detection thresholds.
- **Alert and response actions** — Configurable responses including logging, notifications, and process termination.
- **Lightweight and extensible** — Minimal dependencies with a modular architecture for adding custom detection rules.

## Requirements

- Python 3.8 or higher

## Installation

Clone the repository and install the package:

```bash
git clone https://github.com/im0d00/ransomwareshield.git
cd ransomwareshield
pip install -e .
```

## Quick Start

### Basic Usage

```python
from ransomwareshield import RansomwareShield

# Initialize with default settings
shield = RansomwareShield()

# Monitor a specific directory
shield.monitor("/path/to/protected/directory")

# Start monitoring
shield.start()
```

### Using a Configuration File

```python
from ransomwareshield import RansomwareShield

shield = RansomwareShield.from_config("config.yaml")
shield.start()
```

### Command-Line Interface

```bash
# Monitor the current directory with default settings
ransomwareshield --watch .

# Monitor with a configuration file
ransomwareshield --config config.yaml

# Monitor with verbose logging
ransomwareshield --watch /home/user/documents --verbose
```

## Configuration

RansomwareShield can be configured using a YAML file. See [`examples/config.yaml`](examples/config.yaml) for a complete example.

Key configuration options:

| Option | Description | Default |
|--------|-------------|---------|
| `watch_directories` | List of directories to monitor | `["."]` |
| `file_extensions` | File extensions to watch (empty means all) | `[]` |
| `entropy_threshold` | Entropy level to flag as suspicious (0.0–8.0) | `7.5` |
| `max_changes_per_second` | Maximum file changes per second before alerting | `10` |
| `action` | Response action (`log`, `alert`, `kill_process`) | `log` |
| `log_file` | Path to the log file | `ransomwareshield.log` |

## Examples

See the [`examples/`](examples/) directory for:

- [`config.yaml`](examples/config.yaml) — Sample configuration file with detailed comments
- [`basic_usage.py`](examples/basic_usage.py) — Basic monitoring setup
- [`custom_rules.py`](examples/custom_rules.py) — Adding custom detection rules

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a pull request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.