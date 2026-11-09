"""Shared fixtures for penetration_testing unit tests.

All tests are offline: no fixture performs real network I/O. Where a bridged
module would touch the network it is monkeypatched.
"""

from __future__ import annotations

import logging
import textwrap

import pytest

from penetration_testing.configuration import load_settings
from penetration_testing.evidence.evidence_store import EvidenceStore
from penetration_testing.llm_client import OpenRouterClient
from penetration_testing.security.scope_manager import ScopeManager

logging.disable(logging.CRITICAL)


def _config_xml(perms: str = "", extra_target_body: str = "") -> str:
    perms = perms or (
        "<recon>true</recon><tls_inspection>true</tls_inspection>"
        "<header_analysis>true</header_analysis>"
        "<subdomain_takeover>true</subdomain_takeover>"
    )
    return textwrap.dedent(f"""\
        <?xml version="1.0"?>
        <artex_pentest>
          <engagement>
            <max_iterations>10</max_iterations>
            <max_runtime_seconds>60</max_runtime_seconds>
            <max_tasks>20</max_tasks>
          </engagement>
          <targets>
            <target id="t1">
              <urls>
                <url>https://example.com</url>
              </urls>
              <allowed_domains>example.com</allowed_domains>
              <allow_wildcard_subdomains>true</allow_wildcard_subdomains>
              <allowed_protocols>https</allowed_protocols>
              <allowed_ports>443</allowed_ports>
              <excluded_paths>/admin</excluded_paths>
              {extra_target_body}
              <permissions>{perms}</permissions>
            </target>
          </targets>
        </artex_pentest>
    """)


@pytest.fixture
def write_config(tmp_path):
    def _write(perms: str = "", extra_target_body: str = "") -> str:
        p = tmp_path / "config.xml"
        p.write_text(_config_xml(perms, extra_target_body))
        return str(p)
    return _write


@pytest.fixture
def settings(write_config):
    return load_settings(write_config())


@pytest.fixture
def target(settings):
    return settings.get_target("t1")


@pytest.fixture
def scope(settings):
    return ScopeManager(settings)


@pytest.fixture
def evidence():
    return EvidenceStore(enabled=True)


@pytest.fixture
def llm():
    return OpenRouterClient(api_key="")  # unavailable -> deterministic paths
