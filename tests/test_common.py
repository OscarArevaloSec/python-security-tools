"""Tests for shared helpers in common.py."""
import pytest

import common


def test_parse_ports_list_and_range():
    assert common.parse_ports("80,443,22") == [22, 80, 443]
    assert common.parse_ports("20-22") == [20, 21, 22]
    assert common.parse_ports("443, 80 , 80") == [80, 443]  # dedup + whitespace


def test_parse_ports_rejects_bad_range():
    with pytest.raises(ValueError):
        common.parse_ports("100-1")


def test_parse_ports_rejects_out_of_bounds():
    with pytest.raises(ValueError):
        common.parse_ports("70000")


def test_parse_ports_rejects_empty():
    with pytest.raises(ValueError):
        common.parse_ports(" , ")


def test_expand_target_hostname_passthrough():
    assert common.expand_target("example.com", 256) == ["example.com"]


def test_expand_target_single_host_cidr():
    assert common.expand_target("127.0.0.1/32", 256) == ["127.0.0.1"]


def test_expand_target_small_cidr():
    hosts = common.expand_target("192.168.0.0/30", 256)
    assert hosts == ["192.168.0.1", "192.168.0.2"]


def test_expand_target_respects_max_hosts():
    with pytest.raises(ValueError):
        common.expand_target("10.0.0.0/8", 256)


def test_read_lines_skips_comments_and_blanks(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# comment\n\n127.0.0.1\n  10.0.0.5  \n")
    assert common.read_lines(str(f)) == ["127.0.0.1", "10.0.0.5"]


def test_read_lines_missing_file():
    with pytest.raises(FileNotFoundError):
        common.read_lines("/no/such/file.txt")


def test_run_cmd_missing_binary():
    out, err = common.run_cmd(["definitely_not_a_real_binary_xyz"])
    assert out == ""
    assert "not found" in err.lower()
