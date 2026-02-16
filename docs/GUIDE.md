# RansomwareShield — Detailed Guide

A comprehensive guide to installing, configuring, and using RansomwareShield
for real-time ransomware detection and prevention.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [How Ransomware Detection Works](#2-how-ransomware-detection-works)
3. [Installation](#3-installation)
4. [Getting Started](#4-getting-started)
5. [Command-Line Interface](#5-command-line-interface)
6. [Python API Reference](#6-python-api-reference)
7. [Configuration File Reference](#7-configuration-file-reference)
8. [Detection Mechanisms](#8-detection-mechanisms)
9. [Writing Custom Detection Rules](#9-writing-custom-detection-rules)
10. [Response Actions](#10-response-actions)
11. [Logging and Troubleshooting](#11-logging-and-troubleshooting)
12. [Architecture Overview](#12-architecture-overview)
13. [FAQ](#13-faq)

---

## 1. Introduction

**RansomwareShield** is a lightweight, Python-based tool that monitors your
file system in real time and alerts you when it detects activity patterns
commonly associated with ransomware attacks — such as mass file encryption,
rapid renaming, or the creation of ransom note files.

### What It Does

| Capability | Description |
|---|---|
| **Real-time monitoring** | Watches one or more directories (recursively) for file create, modify, move, and delete events. |
| **Entropy analysis** | Measures the Shannon entropy of modified files — encrypted content has near-maximum entropy (~8.0). |
| **Rate detection** | Flags suspiciously rapid bursts of file changes that exceed a configurable threshold. |
| **Custom rules** | Lets you plug in your own Python functions that inspect every file-system event. |
| **Configurable actions** | Choose between logging, printing alerts, or sending SIGSTOP to the offending process. |

### What It Does *Not* Do

RansomwareShield is a **detection and alerting** tool. It is not a full
antivirus suite, a sandbox, or a backup solution. For comprehensive
protection you should combine it with regular backups, endpoint security
software, and good security hygiene.

---

## 2. How Ransomware Detection Works

Ransomware typically follows a recognizable pattern when it attacks:

1. **Enumeration** — It scans the file system looking for valuable files
   (documents, images, databases, etc.).
2. **Encryption** — Each target file is read, encrypted (often with AES or
   RSA), and written back — either in place or with a new extension such as
   `.locked` or `.encrypted`.
3. **Ransom note** — A text or HTML file is dropped in every affected
   directory instructing the victim to pay.
4. **Deletion** — Original unencrypted files and shadow copies may be
   deleted to prevent recovery.

RansomwareShield targets steps 2–4 with three complementary detection
strategies:

### 2.1 Entropy Analysis

Shannon entropy measures how "random" a sequence of bytes is. Plaintext
documents, images, and source code typically have entropy well below 7.0.
Encrypted (or compressed) data has entropy close to the theoretical maximum
of 8.0 bits per byte.

When a monitored file is modified, RansomwareShield reads the new content
and calculates its entropy. If the value exceeds the configured threshold
(default **7.5**), an alert is raised.

```
Entropy scale (bits per byte):

0.0 ──────── 4.0 ──────── 7.0 ── 7.5 ── 8.0
 │            │            │      │      │
 uniform    text/code    images  ⚠ flag  max
 (all same                       │
  byte)                    encrypted /
                           compressed
```

### 2.2 Rate-Based Detection

Even if individual file modifications look benign, ransomware operates at
high speed — encrypting hundreds or thousands of files per second.
RansomwareShield counts the number of file-system events within a sliding
one-second window and raises an alert when the count exceeds
`max_changes_per_second` (default **10**).

### 2.3 Custom Rules

Neither entropy nor rate detection covers every ransomware behavior. Custom
rules let you add your own checks — for example, detecting the creation of
known ransom-note filenames or the renaming of files to suspicious
extensions.

---

## 3. Installation

### 3.1 Prerequisites

* **Python 3.8** or higher
* **pip** (comes with Python on most platforms)
* A Unix-like OS (Linux / macOS) or Windows

### 3.2 Clone and Install

```bash
# Clone the repository
git clone https://github.com/im0d00/ransomwareshield.git
cd ransomwareshield

# (Recommended) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Linux / macOS
# .venv\Scripts\activate    # Windows

# Install in editable (development) mode
pip install -e .
```

After installation the `ransomwareshield` command is available in your
`PATH` (inside the virtual environment) and `from ransomwareshield import
RansomwareShield` works in Python.

### 3.3 Verify the Installation

```bash
# Check the CLI
ransomwareshield --help

# Check the Python import
python -c "from ransomwareshield import RansomwareShield; print('OK')"
```

### 3.4 Dependencies

RansomwareShield has only two runtime dependencies, both installed
automatically by pip:

| Package | Purpose |
|---|---|
| [watchdog](https://pypi.org/project/watchdog/) ≥ 3.0 | Cross-platform file-system event monitoring |
| [PyYAML](https://pypi.org/project/PyYAML/) ≥ 6.0 | YAML configuration file parsing |

---

## 4. Getting Started

This section walks you through monitoring a directory for the first time.

### 4.1 Quick Start (CLI)

Open a terminal and run:

```bash
ransomwareshield --watch /path/to/directory --verbose
```

RansomwareShield starts watching `/path/to/directory` recursively. In
another terminal, try creating or modifying files in that directory — you
will see log messages appear.

Press **Ctrl+C** to stop.

### 4.2 Quick Start (Python)

```python
from ransomwareshield import RansomwareShield

shield = RansomwareShield(verbose=True)
shield.monitor("/path/to/directory")
shield.start()   # blocks until Ctrl+C
```

### 4.3 Watching Multiple Directories

```python
shield = RansomwareShield()
shield.monitor("/home/user/documents")
shield.monitor("/home/user/pictures")
shield.monitor("/home/user/desktop")
shield.start()
```

Or via CLI:

```bash
ransomwareshield --watch /home/user/documents /home/user/pictures /home/user/desktop
```

### 4.4 Using a Configuration File

For persistent setups, store your settings in a YAML file (see
[Section 7](#7-configuration-file-reference) for all options):

```yaml
# my_config.yaml
watch_directories:
  - "/home/user/documents"
  - "/home/user/pictures"
entropy_threshold: 7.2
max_changes_per_second: 15
action: "alert"
log_file: "shield.log"
verbose: false
```

Then start with:

```bash
ransomwareshield --config my_config.yaml
```

Or from Python:

```python
from ransomwareshield import RansomwareShield

shield = RansomwareShield.from_config("my_config.yaml")
shield.start()
```

---

## 5. Command-Line Interface

```
usage: ransomwareshield [-h] [--watch DIR [DIR ...]] [--config FILE]
                        [--verbose] [--entropy-threshold FLOAT]
                        [--max-changes INT]
                        [--action {log,alert,kill_process}]
```

### Flags

| Flag | Description |
|---|---|
| `--watch DIR [DIR ...]` | One or more directories to monitor. Mutually exclusive with `--config`. |
| `--config FILE` | Path to a YAML configuration file. CLI flags can override config values when used together with `--verbose`. |
| `--verbose` | Enable debug-level logging (much more detailed output). |
| `--entropy-threshold FLOAT` | Override the entropy threshold (0.0–8.0). Only used with `--watch`. |
| `--max-changes INT` | Override the maximum changes-per-second limit. Only used with `--watch`. |
| `--action {log,alert,kill_process}` | Override the response action. Only used with `--watch`. |
| `-h, --help` | Show the help message and exit. |

### Examples

```bash
# Watch the current directory with defaults
ransomwareshield --watch .

# Watch two directories with a lower entropy threshold
ransomwareshield --watch /data /backups --entropy-threshold 7.0

# Use a config file with verbose override
ransomwareshield --config production.yaml --verbose

# Alert to stderr on detection
ransomwareshield --watch /important --action alert
```

---

## 6. Python API Reference

### `RansomwareShield` Class

**Import:**

```python
from ransomwareshield import RansomwareShield
```

#### Constructor

```python
RansomwareShield(
    entropy_threshold: float = 7.5,
    max_changes_per_second: int = 10,
    file_extensions: list[str] | None = None,
    action: str = "log",
    log_file: str | None = None,
    verbose: bool = False,
)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `entropy_threshold` | `float` | `7.5` | File entropy at or above this value triggers an alert. Valid range: 0.0–8.0. |
| `max_changes_per_second` | `int` | `10` | File-system events per second that trigger rate-based alerts. |
| `file_extensions` | `list[str]` | `[]` (all files) | Only monitor files with these extensions (e.g. `[".docx", ".pdf"]`). An empty list means all files. |
| `action` | `str` | `"log"` | Response action: `"log"`, `"alert"`, or `"kill_process"`. See [Section 10](#10-response-actions). |
| `log_file` | `str \| None` | `None` | If set, log messages are also written to this file. |
| `verbose` | `bool` | `False` | When `True`, sets log level to `DEBUG` for more detailed output. |

#### `RansomwareShield.from_config(path)` — class method

```python
shield = RansomwareShield.from_config("config.yaml")
```

Creates and returns a fully configured `RansomwareShield` instance from a
YAML file. Directories listed under `watch_directories` are automatically
registered.

| Parameter | Type | Description |
|---|---|---|
| `path` | `str` | Path to the YAML configuration file. |

**Returns:** `RansomwareShield`

#### `shield.monitor(directory)`

```python
shield.monitor("/home/user/documents")
```

Registers a directory for monitoring. Can be called multiple times before
`start()`. The directory is watched **recursively** (all sub-directories
are included).

| Parameter | Type | Description |
|---|---|---|
| `directory` | `str` | Absolute or relative path to the directory. |

#### `shield.add_rule(name, rule_fn)`

```python
shield.add_rule("my_rule", my_detection_function)
```

Registers a custom detection rule. See
[Section 9](#9-writing-custom-detection-rules) for a full tutorial.

| Parameter | Type | Description |
|---|---|---|
| `name` | `str` | A unique name for the rule (used in alert messages). |
| `rule_fn` | `Callable` | A function that receives a `watchdog.events.FileSystemEvent` and returns `True` if the event is suspicious. |

#### `shield.start()`

Starts the file-system observer and blocks the current thread. Monitoring
continues until `shield.stop()` is called or a `KeyboardInterrupt`
(Ctrl+C) is received.

If no directories have been registered via `monitor()`, a warning is logged
and the method returns immediately.

#### `shield.stop()`

Gracefully stops the file-system observer and releases resources. Safe to
call even if monitoring is not active.

### Entropy Utilities

These lower-level functions are available if you need to calculate entropy
directly:

```python
from ransomwareshield.entropy import calculate_entropy, file_entropy
```

#### `calculate_entropy(data: bytes) -> float`

Computes the Shannon entropy of a byte sequence. Returns a value between
0.0 (completely uniform — e.g. all zeros) and 8.0 (maximally random).

#### `file_entropy(filepath: str) -> float`

Reads the given file in binary mode and returns its Shannon entropy.
Returns `0.0` if the file cannot be read.

---

## 7. Configuration File Reference

RansomwareShield configuration files use YAML syntax. Below is a complete
example with every supported option:

```yaml
# Directories to monitor (recursively).
watch_directories:
  - "/home/user/documents"
  - "/home/user/pictures"

# Only monitor files with these extensions.
# Leave empty (or omit) to monitor ALL file types.
file_extensions:
  - ".docx"
  - ".xlsx"
  - ".pdf"
  - ".jpg"
  - ".png"

# Shannon entropy threshold (float, 0.0 – 8.0).
# Files with entropy >= this value after modification are flagged.
# Lower values = more sensitive (more false positives).
# Higher values = less sensitive (may miss some attacks).
entropy_threshold: 7.5

# Maximum file change events per second before alerting.
# Ransomware typically operates at very high speed.
max_changes_per_second: 10

# Response action when suspicious activity is detected.
#   "log"          — Write a WARNING to the log (default).
#   "alert"        — Also print an immediate message to stderr.
#   "kill_process" — Send SIGSTOP to the offending process (see docs).
action: "log"

# Path to a log file. Omit or set to null for console-only logging.
log_file: "ransomwareshield.log"

# Enable debug-level logging.
verbose: false
```

### Option Details

| Key | Type | Default | Notes |
|---|---|---|---|
| `watch_directories` | list of strings | `["."]` | Absolute or relative paths. Each is watched recursively. |
| `file_extensions` | list of strings | `[]` | Include the leading dot (e.g. `".pdf"`). Empty list = all files. |
| `entropy_threshold` | float | `7.5` | Recommended range: 7.0–7.8. Values below 7.0 produce many false positives on compressed files (ZIP, JPEG, PNG). |
| `max_changes_per_second` | integer | `10` | Set higher (e.g. 50) on systems with naturally high I/O, or lower (e.g. 5) for very sensitive monitoring. |
| `action` | string | `"log"` | One of `"log"`, `"alert"`, `"kill_process"`. |
| `log_file` | string or null | `null` | When set, a `FileHandler` is added to the logger. |
| `verbose` | boolean | `false` | Useful for debugging; produces a lot of output. |

---

## 8. Detection Mechanisms

### 8.1 Entropy Analysis (Built-in)

**When:** Every time a monitored file is **modified**.

**How it works:**

1. The event handler reads the full content of the modified file.
2. Shannon entropy is calculated byte-by-byte using the formula:

   ```
   H = -Σ p(x) · log₂(p(x))
   ```

   where `p(x)` is the probability of byte value `x` appearing.

3. If `H ≥ entropy_threshold`, an alert is raised.

**Tuning tips:**

* JPEG, PNG, and ZIP files are already compressed and have naturally high
  entropy (~7.5–7.9). If you monitor these extensions you may get false
  positives. Either raise the threshold to 7.8+ or exclude them with
  `file_extensions`.
* Plain text and Office documents typically have entropy between 3.0 and
  6.5. A threshold of 7.0–7.5 works well for these.
* To test, create a file of random bytes and watch the alert fire:
  ```bash
  dd if=/dev/urandom of=/watched/dir/test.bin bs=1K count=1
  ```

### 8.2 Rate-Based Detection (Built-in)

**When:** Every file **create**, **modify**, **move**, or **delete** event.

**How it works:**

1. Each event's timestamp is recorded in a sliding window.
2. Events older than 2 seconds are discarded.
3. If the number of events within the last 1 second exceeds
   `max_changes_per_second`, an alert is raised.
4. After an alert fires, a 5-second cooldown prevents alert flooding.

**Tuning tips:**

* Build tools, package managers, and IDEs can trigger many file changes at
  once. Set `max_changes_per_second` high enough to avoid false positives
  during normal development work (e.g. 20–50).
* On a file server where bulk changes are unusual, a low value (e.g. 5)
  increases sensitivity.

### 8.3 Custom Rules

See [Section 9](#9-writing-custom-detection-rules) below.

---

## 9. Writing Custom Detection Rules

Custom rules let you extend RansomwareShield with your own logic. A rule is
any Python callable that:

1. Accepts a single argument — a
   [`watchdog.events.FileSystemEvent`](https://python-watchdog.readthedocs.io/en/stable/api.html#event-classes)
   object.
2. Returns `True` if the event is **suspicious**, or `False` / `None`
   otherwise.

### 9.1 Event Object Quick Reference

| Attribute | Type | Available on | Description |
|---|---|---|---|
| `event.src_path` | `str` | All events | Path to the affected file. |
| `event.dest_path` | `str` | Move events only | Destination path of a moved file. |
| `event.is_directory` | `bool` | All events | Whether the event is about a directory. |
| `event.event_type` | `str` | All events | One of `"created"`, `"modified"`, `"moved"`, `"deleted"`. |

### 9.2 Step-by-Step: Detect Ransom Notes

Let's write a rule that fires when a file with a suspicious name is
created:

```python
import os
from ransomwareshield import RansomwareShield

# Step 1: Define the detection function
def detect_ransom_note(event):
    """Alert when a common ransom-note filename is created."""
    known_names = [
        "README.txt",
        "DECRYPT_INSTRUCTIONS.txt",
        "HOW_TO_RECOVER.txt",
        "HELP_DECRYPT.html",
    ]
    filename = os.path.basename(getattr(event, "src_path", ""))
    return filename in known_names

# Step 2: Register it
shield = RansomwareShield(verbose=True)
shield.add_rule("ransom_note_detection", detect_ransom_note)

# Step 3: Monitor and start
shield.monitor("/home/user/documents")
shield.start()
```

When a file named `DECRYPT_INSTRUCTIONS.txt` appears in the watched
directory, you will see:

```
2026-01-15 10:23:45 [WARNING] ALERT — Custom rule 'ransom_note_detection' triggered | file: /home/user/documents/DECRYPT_INSTRUCTIONS.txt
```

### 9.3 Step-by-Step: Detect Suspicious Extension Changes

Ransomware often renames files by appending an extension such as `.locked`:

```python
import os
from ransomwareshield import RansomwareShield

def detect_extension_change(event):
    """Alert when a file is renamed to a suspicious extension."""
    suspicious = [".locked", ".encrypted", ".crypt", ".enc", ".pay"]
    dest = getattr(event, "dest_path", "")
    _, ext = os.path.splitext(dest)
    return ext.lower() in suspicious

shield = RansomwareShield()
shield.add_rule("suspicious_extension", detect_extension_change)
shield.monitor("/home/user/documents")
shield.start()
```

### 9.4 Combining Multiple Rules

You can register as many rules as you need. Each is evaluated independently
for every file-system event:

```python
shield.add_rule("ransom_note", detect_ransom_note)
shield.add_rule("extension_change", detect_extension_change)
shield.add_rule("large_file_delete", detect_large_delete)
```

### 9.5 Error Handling in Custom Rules

If a custom rule raises an exception, RansomwareShield catches it, logs a
debug message, and continues processing. Your rule will not crash the
monitor.

---

## 10. Response Actions

The `action` setting controls what RansomwareShield does when it detects
suspicious activity.

### 10.1 `"log"` (default)

Writes a `WARNING`-level message to the configured logger (console and/or
log file). This is the safest option and is recommended for initial
deployment.

**Example output:**

```
2026-01-15 10:23:45 [WARNING] ALERT — High entropy (7.92) detected after modification | file: /docs/report.docx
```

### 10.2 `"alert"`

Does everything `"log"` does, **plus** prints an immediate message to
**stderr**. Useful when you are piping stdout elsewhere but still want
immediate visibility.

**Example output (stderr):**

```
[RansomwareShield] ALERT — High entropy (7.92) detected after modification | file: /docs/report.docx
```

### 10.3 `"kill_process"`

> ⚠️ **Use with caution.** This action is intended for advanced/production
> deployments.

In addition to logging, this action sends `SIGSTOP` to the current process.
In a production environment you would modify this to identify the PID of
the process performing the suspicious file operations and send `SIGSTOP` or
`SIGKILL` to *that* process instead.

The current implementation stops the RansomwareShield process itself as a
safe demonstration. To implement real process identification, you would
extend the `ShieldEventHandler._respond()` method in
`src/ransomwareshield/monitor.py`.

---

## 11. Logging and Troubleshooting

### 11.1 Log Levels

| Level | When used |
|---|---|
| `DEBUG` | Detailed internal events (enabled with `verbose: true`). |
| `INFO` | Normal operational messages (start, stop, directory registered). |
| `WARNING` | **Detection alerts** — every alert is logged at this level. |
| `CRITICAL` | The `kill_process` action was triggered. |

### 11.2 Log Format

```
2026-01-15 10:23:45 [WARNING] ALERT — High entropy (7.92) detected after modification | file: /docs/report.docx
│                    │         │
│                    │         └── Alert details and affected file path
│                    └── Log level
└── Timestamp (YYYY-MM-DD HH:MM:SS)
```

### 11.3 Writing to a Log File

Set `log_file` in the configuration file or constructor:

```yaml
log_file: "/var/log/ransomwareshield.log"
```

Or in Python:

```python
shield = RansomwareShield(log_file="/var/log/ransomwareshield.log")
```

Both console and file handlers are active simultaneously.

### 11.4 Common Issues

| Problem | Solution |
|---|---|
| **No output at all** | Make sure you called `shield.monitor()` before `shield.start()`. Check that the directory exists. |
| **Too many false positives** | Raise `entropy_threshold` (e.g. to 7.8) or raise `max_changes_per_second`. Exclude compressed file types via `file_extensions`. |
| **Misses known ransomware** | Lower `entropy_threshold` (e.g. to 7.0). Add custom rules for known ransom-note filenames and extensions. |
| **`ModuleNotFoundError`** | Run `pip install -e .` from the repository root. Make sure you are in the correct virtual environment. |
| **Permission denied errors** | Ensure the user running RansomwareShield has read access to the monitored directories. |
| **High CPU usage** | Monitoring very large directory trees (millions of files) can be expensive. Narrow `watch_directories` to specific sub-trees. |

---

## 12. Architecture Overview

```
┌──────────────────────────────────────────────────┐
│                     CLI                          │
│              (cli.py — argparse)                 │
└────────────────────┬─────────────────────────────┘
                     │
                     ▼
┌──────────────────────────────────────────────────┐
│              RansomwareShield                    │
│          (shield.py — public API)                │
│                                                  │
│  • from_config()   • monitor()                   │
│  • add_rule()      • start() / stop()            │
└────────────────────┬─────────────────────────────┘
                     │ creates
                     ▼
┌──────────────────────────────────────────────────┐
│           ShieldEventHandler                     │
│     (monitor.py — watchdog handler)              │
│                                                  │
│  • on_created()    • _check_rate()               │
│  • on_modified()   • _matches_extensions()       │
│  • on_moved()      • _respond()                  │
│  • on_deleted()                                  │
└────────────┬─────────────────┬───────────────────┘
             │                 │
             ▼                 ▼
┌────────────────────┐ ┌──────────────────────┐
│   Entropy Module   │ │   Custom Rules       │
│   (entropy.py)     │ │   (user-provided)    │
│                    │ │                      │
│ calculate_entropy()│ │   rule_fn(event)     │
│ file_entropy()     │ │   → True / False     │
└────────────────────┘ └──────────────────────┘
```

### Module Responsibilities

| Module | File | Purpose |
|---|---|---|
| **Package init** | `__init__.py` | Exports `RansomwareShield` and `__version__`. |
| **Shield** | `shield.py` | Owns configuration, the `watchdog.Observer`, and the public API. |
| **Monitor** | `monitor.py` | Implements `ShieldEventHandler` (subclass of `watchdog.FileSystemEventHandler`). Contains all detection logic. |
| **Entropy** | `entropy.py` | Pure functions for Shannon entropy calculation. No side effects. |
| **CLI** | `cli.py` | Argument parsing and entry point for the `ransomwareshield` command. |

---

## 13. FAQ

### Q: Does RansomwareShield work on Windows?

**A:** Yes. The `watchdog` library supports Windows, macOS, and Linux.
However, the `kill_process` action uses Unix signals (`SIGSTOP`) and will
not work on Windows — use `"log"` or `"alert"` instead.

### Q: Can I monitor the entire root filesystem (`/`)?

**A:** Technically yes, but it is not recommended. Monitoring `/` generates
an enormous number of events from system processes and will likely produce
many false positives. Monitor specific directories that contain valuable
data instead.

### Q: How does the entropy threshold affect false positives?

**A:** Lower thresholds flag more files, including legitimately compressed
formats (JPEG, PNG, ZIP, GZ). Higher thresholds reduce false positives but
may miss ransomware that uses weaker encryption. Start with the default
(7.5) and adjust based on your environment.

### Q: Can I run RansomwareShield as a background service?

**A:** Yes. You can run it under `systemd`, `supervisord`, or any process
manager. Example systemd unit:

```ini
[Unit]
Description=RansomwareShield File Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ransomwareshield --config /etc/ransomwareshield/config.yaml
Restart=on-failure
User=ransomwareshield

[Install]
WantedBy=multi-user.target
```

### Q: How do I test that my setup is working?

**A:** In a separate terminal, create a file with high-entropy content in a
monitored directory:

```bash
dd if=/dev/urandom of=/watched/directory/test.bin bs=1K count=10
```

You should see an entropy alert immediately.

### Q: Can custom rules access the file contents?

**A:** Yes. The `event.src_path` attribute gives you the file path. You can
open and read it inside your rule function. Be aware that for `deleted`
events the file no longer exists.

### Q: What happens if a custom rule throws an exception?

**A:** RansomwareShield catches all exceptions from custom rules, logs them
at `DEBUG` level, and continues processing. The monitor is not interrupted.

### Q: Is there a performance impact?

**A:** The entropy check reads the full file for every `modified` event.
For very large files (multiple GB) this can be slow. To limit the impact,
use `file_extensions` to restrict which file types are checked, or monitor
only directories that contain reasonably-sized files.
