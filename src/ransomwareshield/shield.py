"""Core RansomwareShield class — public API."""

import logging
import time
from typing import Callable, Dict, List, Optional

import yaml
from watchdog.observers import Observer

from ransomwareshield.monitor import ShieldEventHandler

logger = logging.getLogger("ransomwareshield")


class RansomwareShield:
    """Ransomware detection and prevention engine.

    Usage
    -----
    >>> shield = RansomwareShield()
    >>> shield.monitor("/path/to/dir")
    >>> shield.start()       # blocks until stop() or KeyboardInterrupt
    """

    def __init__(
        self,
        entropy_threshold: float = 7.5,
        max_changes_per_second: int = 10,
        file_extensions: Optional[List[str]] = None,
        action: str = "log",
        log_file: Optional[str] = None,
        verbose: bool = False,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.max_changes_per_second = max_changes_per_second
        self.file_extensions = file_extensions or []
        self.action = action
        self.log_file = log_file
        self.verbose = verbose

        self._watch_dirs: List[str] = []
        self._custom_rules: Dict[str, Callable] = {}
        self._observer: Optional[Observer] = None

        self._setup_logging()

    # -- configuration --------------------------------------------------

    @classmethod
    def from_config(cls, path: str) -> "RansomwareShield":
        """Create a RansomwareShield instance from a YAML config file."""
        with open(path, "r") as fh:
            cfg = yaml.safe_load(fh) or {}

        shield = cls(
            entropy_threshold=cfg.get("entropy_threshold", 7.5),
            max_changes_per_second=cfg.get("max_changes_per_second", 10),
            file_extensions=cfg.get("file_extensions", []),
            action=cfg.get("action", "log"),
            log_file=cfg.get("log_file"),
            verbose=cfg.get("verbose", False),
        )

        for directory in cfg.get("watch_directories", ["."]):
            shield.monitor(directory)

        return shield

    # -- public API -----------------------------------------------------

    def monitor(self, directory: str) -> None:
        """Register a directory to be monitored."""
        self._watch_dirs.append(directory)

    def add_rule(self, name: str, rule_fn: Callable) -> None:
        """Register a custom detection rule.

        *rule_fn* receives a ``watchdog.events.FileSystemEvent`` and
        should return ``True`` when the event is suspicious.
        """
        self._custom_rules[name] = rule_fn

    def start(self) -> None:
        """Start monitoring.  Blocks until :meth:`stop` is called."""
        if not self._watch_dirs:
            logger.warning("No directories to monitor — call monitor() first.")
            return

        handler = ShieldEventHandler(
            entropy_threshold=self.entropy_threshold,
            max_changes_per_second=self.max_changes_per_second,
            file_extensions=self.file_extensions,
            action=self.action,
            custom_rules=self._custom_rules,
        )

        self._observer = Observer()
        for d in self._watch_dirs:
            logger.info("Watching directory: %s", d)
            self._observer.schedule(handler, d, recursive=True)

        self._observer.start()
        logger.info("RansomwareShield started.")

        try:
            while self._observer.is_alive():
                self._observer.join(timeout=1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self) -> None:
        """Stop monitoring gracefully."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
            self._observer = None
            logger.info("RansomwareShield stopped.")

    # -- internals ------------------------------------------------------

    def _setup_logging(self) -> None:
        level = logging.DEBUG if self.verbose else logging.INFO
        logger.setLevel(level)

        if not logger.handlers:
            fmt = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )

            console = logging.StreamHandler()
            console.setLevel(level)
            console.setFormatter(fmt)
            logger.addHandler(console)

            if self.log_file:
                fh = logging.FileHandler(self.log_file)
                fh.setLevel(level)
                fh.setFormatter(fmt)
                logger.addHandler(fh)
