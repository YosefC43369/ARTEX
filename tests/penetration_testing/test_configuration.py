import pytest

from penetration_testing.configuration import load_settings
from penetration_testing.constants import SAFETY_CEILINGS
from penetration_testing.exceptions import ConfigurationError


def test_loads_valid_config(settings):
    assert "t1" in settings.targets
    t = settings.get_target("t1")
    assert t.domain == "example.com"
    assert t.has_permission("recon") is True
    assert t.has_permission("port_scan") is False  # unlisted => fail closed


def test_missing_file_fails_closed(tmp_path):
    with pytest.raises(ConfigurationError):
        load_settings(str(tmp_path / "nope.xml"))


def test_invalid_xml_fails_closed(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<artex_pentest><targets><target></broken>")
    with pytest.raises(ConfigurationError):
        load_settings(str(p))


def test_no_targets_fails_closed(tmp_path):
    p = tmp_path / "empty.xml"
    p.write_text("<artex_pentest><targets></targets></artex_pentest>")
    with pytest.raises(ConfigurationError):
        load_settings(str(p))


def test_unknown_capability_fails_closed(write_config):
    path = write_config(perms="<not_a_real_capability>true</not_a_real_capability>")
    with pytest.raises(ConfigurationError):
        load_settings(path)


def test_limits_clamped_to_ceiling(tmp_path):
    p = tmp_path / "big.xml"
    p.write_text("""<artex_pentest>
      <engagement><max_iterations>99999</max_iterations>
        <max_requests_per_second>9999</max_requests_per_second></engagement>
      <targets><target id="x"><domain>example.com</domain>
        <permissions><recon>true</recon></permissions></target></targets>
    </artex_pentest>""")
    s = load_settings(str(p))
    assert s.limits.max_iterations == SAFETY_CEILINGS["max_iterations"]
    assert s.limits.max_requests_per_second == SAFETY_CEILINGS["max_requests_per_second"]
