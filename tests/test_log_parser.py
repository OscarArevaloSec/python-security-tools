"""Tests for auth-log parsing and brute-force detection."""
import log_parser


def test_all_patterns_compile():
    # Regression guard for the [\u:] escape bug that crashed the module.
    assert "su" in log_parser.PATTERNS
    assert "new_group" in log_parser.PATTERNS


SAMPLE = """\
Jun  1 10:00:01 host sshd[111]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2
Jun  1 10:00:02 host sshd[112]: Failed password for root from 10.0.0.9 port 22 ssh2
Jun  1 10:00:03 host sshd[113]: Failed password for root from 10.0.0.9 port 22 ssh2
Jun  1 10:05:10 host sshd[120]: Accepted password for oscar from 10.0.0.5 port 22 ssh2
"""


def test_ssh_fail_and_brute_force(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(SAMPLE)
    results, total = log_parser.parse_file(str(f), "all", brute_threshold=3, log_type="auth")
    assert total == 4
    assert len(results["ssh_fail"]) == 3
    assert len(results["ssh_success"]) == 1
    assert results["brute_force"]
    assert results["brute_force"][0]["ip"] == "10.0.0.9"
    assert results["brute_force"][0]["count"] == 3


def test_brute_force_threshold_not_met(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(SAMPLE)
    results, _ = log_parser.parse_file(str(f), "all", brute_threshold=10, log_type="auth")
    assert results["brute_force"] == []
