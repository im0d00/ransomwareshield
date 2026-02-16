"""Tests for the RansomwareShield class and ShieldEventHandler."""

import os
import tempfile
import time

import yaml

from ransomwareshield.shield import RansomwareShield
from ransomwareshield.monitor import ShieldEventHandler


class TestRansomwareShieldInit:
    def test_default_values(self):
        shield = RansomwareShield()
        assert shield.entropy_threshold == 7.5
        assert shield.max_changes_per_second == 10
        assert shield.file_extensions == []
        assert shield.action == "log"
        assert shield.verbose is False

    def test_custom_values(self):
        shield = RansomwareShield(
            entropy_threshold=6.0,
            max_changes_per_second=5,
            file_extensions=[".doc", ".pdf"],
            action="alert",
            verbose=True,
        )
        assert shield.entropy_threshold == 6.0
        assert shield.max_changes_per_second == 5
        assert shield.file_extensions == [".doc", ".pdf"]
        assert shield.action == "alert"
        assert shield.verbose is True


class TestMonitor:
    def test_monitor_adds_directory(self):
        shield = RansomwareShield()
        shield.monitor("/tmp")
        assert "/tmp" in shield._watch_dirs

    def test_monitor_multiple_directories(self):
        shield = RansomwareShield()
        shield.monitor("/tmp")
        shield.monitor("/var")
        assert len(shield._watch_dirs) == 2


class TestAddRule:
    def test_add_rule_registers_callable(self):
        shield = RansomwareShield()
        shield.add_rule("test_rule", lambda e: False)
        assert "test_rule" in shield._custom_rules

    def test_multiple_rules(self):
        shield = RansomwareShield()
        shield.add_rule("r1", lambda e: False)
        shield.add_rule("r2", lambda e: True)
        assert len(shield._custom_rules) == 2


class TestFromConfig:
    def test_from_config_loads_yaml(self):
        cfg = {
            "watch_directories": ["/tmp/test_dir_a"],
            "entropy_threshold": 6.5,
            "max_changes_per_second": 20,
            "file_extensions": [".txt"],
            "action": "alert",
            "log_file": None,
            "verbose": True,
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(cfg, f)
            path = f.name
        try:
            shield = RansomwareShield.from_config(path)
            assert shield.entropy_threshold == 6.5
            assert shield.max_changes_per_second == 20
            assert shield.file_extensions == [".txt"]
            assert shield.action == "alert"
            assert "/tmp/test_dir_a" in shield._watch_dirs
        finally:
            os.unlink(path)

    def test_from_config_defaults(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("{}")
            path = f.name
        try:
            shield = RansomwareShield.from_config(path)
            assert shield.entropy_threshold == 7.5
            assert shield.action == "log"
        finally:
            os.unlink(path)


class TestShieldEventHandler:
    def test_matches_extensions_empty_means_all(self):
        handler = ShieldEventHandler(file_extensions=[])
        assert handler._matches_extensions("file.txt") is True
        assert handler._matches_extensions("file.doc") is True

    def test_matches_extensions_filter(self):
        handler = ShieldEventHandler(file_extensions=[".txt", ".pdf"])
        assert handler._matches_extensions("file.txt") is True
        assert handler._matches_extensions("file.pdf") is True
        assert handler._matches_extensions("file.doc") is False

    def test_rate_detection(self):
        handler = ShieldEventHandler(max_changes_per_second=5)
        # Simulate 10 rapid changes
        for _ in range(10):
            handler._record_change()
        assert handler._check_rate() is True


class TestStartStop:
    def test_start_stop_real_directory(self):
        """Start monitoring a real temp directory, then stop."""
        tmpdir = tempfile.mkdtemp()
        try:
            shield = RansomwareShield()
            shield.monitor(tmpdir)

            import threading

            def delayed_stop():
                time.sleep(1)
                shield.stop()

            t = threading.Thread(target=delayed_stop, daemon=True)
            t.start()
            shield.start()  # should return after stop() is called
        finally:
            os.rmdir(tmpdir)

    def test_start_no_dirs_returns_immediately(self):
        shield = RansomwareShield()
        shield.start()  # should return immediately without error
