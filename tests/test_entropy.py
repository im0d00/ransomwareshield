"""Tests for the entropy module."""

import os
import tempfile

from ransomwareshield.entropy import calculate_entropy, file_entropy


class TestCalculateEntropy:
    def test_empty_data_returns_zero(self):
        assert calculate_entropy(b"") == 0.0

    def test_single_byte_returns_zero(self):
        assert calculate_entropy(b"\x00") == 0.0

    def test_uniform_data_returns_zero(self):
        data = b"a" * 1000
        assert calculate_entropy(data) == 0.0

    def test_random_data_has_high_entropy(self):
        import random

        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(10000))
        ent = calculate_entropy(data)
        assert ent > 7.5

    def test_text_has_moderate_entropy(self):
        data = b"The quick brown fox jumps over the lazy dog. " * 20
        ent = calculate_entropy(data)
        assert 3.0 < ent < 6.0

    def test_two_byte_values(self):
        data = bytes([0, 1] * 500)
        ent = calculate_entropy(data)
        assert abs(ent - 1.0) < 0.01  # exactly 1 bit


class TestFileEntropy:
    def test_readable_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"Hello World" * 100)
            path = f.name
        try:
            ent = file_entropy(path)
            assert ent > 0
        finally:
            os.unlink(path)

    def test_nonexistent_file_returns_zero(self):
        assert file_entropy("/tmp/nonexistent_file_abc123xyz") == 0.0

    def test_empty_file_returns_zero(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            path = f.name
        try:
            assert file_entropy(path) == 0.0
        finally:
            os.unlink(path)
