"""File-system event handler for ransomware detection."""

import logging
import os
import signal
import time
from typing import Callable, Dict, List, Optional

from watchdog.events import FileSystemEvent, FileSystemEventHandler

from ransomwareshield.entropy import file_entropy

logger = logging.getLogger("ransomwareshield")


class ShieldEventHandler(FileSystemEventHandler):
    """Watchdog event handler that applies detection rules."""

    def __init__(
        self,
        entropy_threshold: float = 7.5,
        max_changes_per_second: int = 10,
        file_extensions: Optional[List[str]] = None,
        action: str = "log",
        custom_rules: Optional[Dict[str, Callable]] = None,
    ) -> None:
        super().__init__()
        self.entropy_threshold = entropy_threshold
        self.max_changes_per_second = max_changes_per_second
        self.file_extensions = file_extensions or []
        self.action = action
        self.custom_rules: Dict[str, Callable] = custom_rules or {}

        # Rate tracking
        self._change_times: List[float] = []
        self._rate_alert_cooldown = 0.0

    # -- helpers --------------------------------------------------------

    def _matches_extensions(self, path: str) -> bool:
        if not self.file_extensions:
            return True
        _, ext = os.path.splitext(path)
        return ext.lower() in (e.lower() for e in self.file_extensions)

    def _record_change(self) -> None:
        now = time.time()
        self._change_times.append(now)
        # Keep only the last 2 seconds of events
        self._change_times = [t for t in self._change_times if now - t <= 2.0]

    def _check_rate(self) -> bool:
        """Return True if the change rate exceeds the threshold."""
        now = time.time()
        if now - self._rate_alert_cooldown < 5.0:
            return False
        recent = [t for t in self._change_times if now - t <= 1.0]
        if len(recent) > self.max_changes_per_second:
            self._rate_alert_cooldown = now
            return True
        return False

    def _respond(self, reason: str, event: FileSystemEvent) -> None:
        src = getattr(event, "src_path", "unknown")
        msg = f"ALERT — {reason} | file: {src}"
        logger.warning(msg)

        if self.action == "alert":
            # Print to stderr as an immediate alert
            import sys

            print(f"[RansomwareShield] {msg}", file=sys.stderr)
        elif self.action == "kill_process":
            logger.critical("Attempting to kill suspicious process (SIGSTOP self as demo)")
            # In a real deployment this would identify the offending PID.
            # Here we send SIGSTOP to our own process group as a safe demo.
            os.kill(os.getpid(), signal.SIGSTOP)

    # -- watchdog overrides ---------------------------------------------

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if not self._matches_extensions(event.src_path):
            return

        self._record_change()

        # Entropy check
        ent = file_entropy(event.src_path)
        if ent >= self.entropy_threshold:
            self._respond(
                f"High entropy ({ent:.2f}) detected after modification",
                event,
            )

        # Rate check
        if self._check_rate():
            self._respond(
                f"Rapid file changes detected (>{self.max_changes_per_second}/s)",
                event,
            )

        # Custom rules
        for name, rule_fn in self.custom_rules.items():
            try:
                if rule_fn(event):
                    self._respond(f"Custom rule '{name}' triggered", event)
            except Exception:
                logger.debug("Custom rule '%s' raised an exception", name, exc_info=True)

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._record_change()

        for name, rule_fn in self.custom_rules.items():
            try:
                if rule_fn(event):
                    self._respond(f"Custom rule '{name}' triggered", event)
            except Exception:
                logger.debug("Custom rule '%s' raised an exception", name, exc_info=True)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._record_change()

        for name, rule_fn in self.custom_rules.items():
            try:
                if rule_fn(event):
                    self._respond(f"Custom rule '{name}' triggered", event)
            except Exception:
                logger.debug("Custom rule '%s' raised an exception", name, exc_info=True)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._record_change()

        if self._check_rate():
            self._respond(
                f"Rapid file deletions detected (>{self.max_changes_per_second}/s)",
                event,
            )
