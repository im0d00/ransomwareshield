"""Tests for the CLI module."""

import os
import tempfile

import yaml

from ransomwareshield.cli import main


class TestCLI:
    def test_help_flag(self):
        """--help should exit with code 0."""
        try:
            main(["--help"])
        except SystemExit as exc:
            assert exc.code == 0

    def test_no_args_exits(self):
        """No arguments should print help and exit with 1."""
        try:
            main([])
        except SystemExit as exc:
            assert exc.code == 1

    def test_config_flag_parses(self):
        """--config should load a valid YAML file and start."""
        tmpdir = tempfile.mkdtemp()
        cfg = {
            "watch_directories": [tmpdir],
            "entropy_threshold": 7.0,
            "action": "log",
        }
        cfg_path = os.path.join(tmpdir, "cfg.yaml")
        with open(cfg_path, "w") as f:
            yaml.dump(cfg, f)

        # We can't easily test a blocking start(), so just verify parsing
        # by importing and checking from_config directly
        from ransomwareshield import RansomwareShield

        shield = RansomwareShield.from_config(cfg_path)
        assert shield.entropy_threshold == 7.0
        assert tmpdir in shield._watch_dirs

        os.unlink(cfg_path)
        os.rmdir(tmpdir)
